/* 
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "harness.h"
#import "SwizzleHelper.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <CoreAudio/CoreAudio.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <getopt.h>
#include <cstdint>

unsigned char *shm_data = NULL;
int verbose = 0;
int print_bytes_only = 0;
t_Mach_Processing_Function Mach_Processing_Function = NULL;
t_AudioHardwareStartServer AudioHardwareStartServer = NULL;
uint64_t *NextObjectID = NULL;
audit_token_t safari_audit_token;

void append_vector(std::vector<uint8_t>& dest, const std::vector<uint8_t>& src) {
    dest.insert(dest.end(), src.begin(), src.end());
}

std::vector<uint8_t> get_standard_trailer() {
    // Add the trailer statically
        std::vector<uint8_t> trailer;

        // Static values for the trailer
        std::vector<uint8_t> msg_trailer_type = {0x00, 0x00, 0x00, 0x00};
        uint32_t msg_trailer_size = 32; // Trailer size is 32 bytes
        verbose_print("Trailer size: %d\n", msg_trailer_size);
        std::vector<std::uint8_t> msg_trailer_size_vec((std::uint8_t*)&msg_trailer_size, (std::uint8_t*)&(msg_trailer_size) + sizeof(std::uint32_t));

        std::vector<uint8_t> msg_seqno = {0x00, 0x00, 0x00, 0x00};
        std::vector<uint8_t> msg_sender = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        // Convert the audit token to a byte vector for the trailer body
        std::vector<uint8_t> trailer_body((uint8_t*)&safari_audit_token, (uint8_t*)&safari_audit_token + sizeof(audit_token_t));

        append_vector(trailer, msg_trailer_type);
        append_vector(trailer, msg_trailer_size_vec);
        append_vector(trailer, msg_seqno);
        append_vector(trailer, msg_sender);
        append_vector(trailer, trailer_body);

        return trailer;
}

void generate_header(FuzzedDataProvider& fuzz_data, uint32_t& msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool_message=false) {
    // Consume bits for message header
    uint32_t msg_bits = fuzz_data.ConsumeIntegral<uint32_t>();

    if (is_ool_message) {
        msg_bits = msg_bits | 0x80000000;
    }

    std::vector<uint8_t> msg_bits_vec((uint8_t*)&msg_bits, (uint8_t*)&msg_bits + sizeof(uint32_t));

    // Check if the message size needs to be generated
    if (msg_size == 0) {
        msg_size = fuzz_data.ConsumeIntegralInRange<uint32_t>(MACH_MSG_HEADER_SIZE, 1000);
    }
    
    std::vector<uint8_t> msg_size_vec((uint8_t*)&msg_size, (uint8_t*)&msg_size + sizeof(uint32_t));
    
    // Consume ports and message ID
    std::vector<uint8_t> msg_remote_port = fuzz_data.ConsumeBytes<uint8_t>(4);
    std::vector<uint8_t> msg_local_port = fuzz_data.ConsumeBytes<uint8_t>(4);
    std::vector<uint8_t> msg_voucher_port = fuzz_data.ConsumeBytes<uint8_t>(4);
    std::vector<uint8_t> msg_id_vec((uint8_t*)&msg_id, (uint8_t*)&msg_id + sizeof(uint32_t));

    // Append all parts to the header vector
    append_vector(header, msg_bits_vec);
    append_vector(header, msg_size_vec);
    append_vector(header, msg_remote_port);
    append_vector(header, msg_local_port);
    append_vector(header, msg_voucher_port);
    append_vector(header, msg_id_vec);
}

// Define valid values for property selectors, scopes, and elements
const std::vector<uint32_t> kValidSelectors = {
    'grup', 'agrp', 'acom', 'amst', 'apcd', 'tap#', 'atap', '****', 0
};

const std::vector<uint32_t> kValidScopes = {
    'glob', 'inpt', 'outp', 'ptru', '****', 0
};

const std::vector<uint32_t> kValidElements = {
    0xFFFFFFFF, 0 // Wildcard and Null
};

// Function to flip a weighted coin using FuzzedDataProvider::ConsumeProbability()
bool flip_weighted_coin(double probability, FuzzedDataProvider& fuzz_data) {
    return fuzz_data.ConsumeProbability<double>() < probability;
}

// Function to choose a random value from a given vector
uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices) {
    return choices[fuzz_data.ConsumeIntegralInRange<size_t>(0, choices.size() - 1)];
}

// Function to add selector information to mach_msg
void add_selector_information(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& body) {
    if (body.size() < 16) {
        return; // Ensure there's enough space to modify the last 16 bytes
    }

    if (flip_weighted_coin(0.95, fuzz_data)) {  // 95% probability
        size_t end = body.size();
        *reinterpret_cast<uint32_t*>(&body[end - 16]) = choose_one_of(fuzz_data, kValidSelectors);
        *reinterpret_cast<uint32_t*>(&body[end - 12]) = choose_one_of(fuzz_data, kValidScopes);
        *reinterpret_cast<uint32_t*>(&body[end - 8])  = choose_one_of(fuzz_data, kValidElements);
    }
}

void generate_body(uint32_t msg_id, FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& body, uint32_t body_size) {
    body = fuzz_data.ConsumeBytes<uint8_t>(body_size);

    if (body.size() < body_size) {
        body.resize(body_size, 0x00);
    }

    std::string msg_id_string = message_id_to_string(static_cast<message_id_enum>(msg_id));
    if (msg_id_string.find("SetProperty") != std::string::npos || 
        msg_id_string.find("GetProperty") != std::string::npos || 
        msg_id_string.find("GetObjectInfo") != std::string::npos) {
        add_selector_information(fuzz_data, body);
    }
}

// Helper function to generate a normal message
std::vector<uint8_t> generate_normal_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, uint32_t msg_size, std::vector<uint8_t>& mach_msg) {
    // HEADER
    std::vector<uint8_t> header;
    generate_header(fuzz_data, msg_size, msg_id, header);

    // BODY
    std::vector<uint8_t> body;
    if (header.size() < msg_size) {
        uint32_t body_size = msg_size - header.size();
        generate_body(msg_id, fuzz_data, body, body_size);
    }

    // Combine header and body. Resize if necessary
    mach_msg.insert(mach_msg.end(), header.begin(), header.end());
    mach_msg.insert(mach_msg.end(), body.begin(), body.end());
    // Will either trim if too long, or pad with zeroes
    mach_msg.resize(msg_size, 0);

    // TRAILER
    std::vector<uint8_t> trailer = get_standard_trailer();
    mach_msg.insert(mach_msg.end(), trailer.begin(), trailer.end());

    return mach_msg;
}

void print_ool_buffer_contents(void *buffer, size_t size) {
    uint8_t *byteBuffer = (uint8_t *)buffer;  // Cast the buffer to a byte pointer

    // Print each byte in hexadecimal format
    printf("OOL Buffer contents (size = %zu bytes):\n", size);
    for (size_t i = 0; i < size; ++i) {
        printf("0x%02x ", byteBuffer[i]);
    }
    printf("\n");
}

// typedef union {
// 	mach_msg_port_descriptor_t            port;
// 	mach_msg_ool_descriptor_t             out_of_line;
// 	mach_msg_ool_ports_descriptor_t       ool_ports;
// 	mach_msg_type_descriptor_t            type;
// 	mach_msg_guarded_port_descriptor_t    guarded_port;
// } mach_msg_descriptor_t;

// Function to safely get a pointer to the element at the given index, or nullptr if out of bounds
template <typename T>
const T* safe_get(const std::vector<T>& vec, size_t index) {
    return (index < vec.size()) ? &vec[index] : nullptr;
}

mach_port_t create_mach_port_with_send_rights() {
    mach_port_t port;
    kern_return_t kr;

    // Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert send right: %s\n", mach_error_string(kr));
        exit(1);
    }

    return port; // Return the port with send rights
}

mach_port_t create_mach_port_with_send_and_receive_rights() {
    mach_port_t port = MACH_PORT_NULL;  // Initialize port variable
    kern_return_t kr;

    // Step 1: Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to allocate Mach port with receive rights: " << mach_error_string(kr) << std::endl;
        exit(1);  // Exit on failure to allocate the port
    }

    // Step 2: Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to insert send right into port: " << mach_error_string(kr) << std::endl;
        mach_port_deallocate(mach_task_self(), port);  // Deallocate the port if adding send right fails
        exit(1);
    }

    return port;
}

void generate_descriptors(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& descriptors, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {

    // Consume a descriptor_count if it hasn't been hardcoded for the message
    if (descriptor_count < 1) {
        descriptor_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 4);
    }

    // Convert descriptor_count to a vector and append
    std::vector<uint8_t> descriptor_count_vec(reinterpret_cast<uint8_t*>(&descriptor_count), reinterpret_cast<uint8_t*>(&descriptor_count) + sizeof(uint32_t));
    append_vector(descriptors, descriptor_count_vec);

    for (uint32_t i = 0; i < descriptor_count; i++) {
        // Use safe_get to safely access the descriptor type
        const mach_msg_descriptor_type_t* type_ptr = safe_get(descriptor_types, i);
        
        // Check if the pointer is valid (not null)
        mach_msg_descriptor_type_t type;
        if (type_ptr != nullptr) {
            type = *type_ptr;
        } else {
            // If no descriptor type is found, use a default or fuzz one
            type = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 2);
        }

        switch (type) {
            case MACH_MSG_OOL_DESCRIPTOR: {
                void* oolBuffer = NULL;
                uint32_t size;
                if (flip_weighted_coin(0.5, fuzz_data)) {
                    // Place plist within OOL data
                    const char* data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>name</key><string>Aggregate Device</string><key>uid</key><string>DillonFrankeAAAAADillonFrankeAAAAADillonFrankeAAAAAAAAAAAAAAAA21</string></dict></plist>";

                    size = strlen(data) + 1;

                    if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&oolBuffer), size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                        printf("Failed to allocate memory buffer\n");
                        // Deallocate previously allocated buffers if allocation fails
                        for (const auto& buffer_pair : ool_buffers) {
                            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(buffer_pair.first), buffer_pair.second);
                        }
                        return;
                    }
                    strncpy((char *)oolBuffer, data, size);
                } else {
                    // Generate random data from the fuzz input for the OOL data
                    uint32_t planned_size = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, MAX_OOL_DATA_SIZE);

                    if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&oolBuffer), planned_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                        printf("Failed to allocate memory buffer\n");
                        // Deallocate previously allocated buffers if allocation fails
                        for (const auto& buffer_pair : ool_buffers) {
                            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(buffer_pair.first), buffer_pair.second);
                        }
                        return;
                    }
                    size = fuzz_data.ConsumeData(oolBuffer, planned_size);
                }

                // Store the allocated buffer and fill it with fuzzed data
                ool_buffers.push_back(std::make_pair(oolBuffer, size));

                if (verbose) {
                    printf("Allocated OOL Buffer contains:\n");
                    print_ool_buffer_contents(oolBuffer, size);
                }

                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_descriptor_t), 0x00);
                mach_msg_ool_descriptor_t* ool_descriptor = reinterpret_cast<mach_msg_ool_descriptor_t*>(descriptor_vec.data());

                // Populate the OOL descriptor fields
                ool_descriptor->size = size;
                ool_descriptor->address = oolBuffer;
                ool_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
                ool_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
                ool_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint8_t>();
                ool_descriptor->type = MACH_MSG_OOL_DESCRIPTOR;

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            case MACH_MSG_PORT_DESCRIPTOR: {
                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_port_descriptor_t), 0x00);
                mach_msg_port_descriptor_t* port_descriptor = reinterpret_cast<mach_msg_port_descriptor_t*>(descriptor_vec.data());

                port_descriptor->name = create_mach_port_with_send_rights();  // Ensure this function is defined
                port_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint32_t>();
                port_descriptor->pad2 = fuzz_data.ConsumeIntegral<uint16_t>();
                port_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint32_t>(16, 26);
                port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_ports_descriptor_t), 0x00);
                mach_msg_ool_ports_descriptor_t* ool_ports_descriptor = reinterpret_cast<mach_msg_ool_ports_descriptor_t*>(descriptor_vec.data());

                uint32_t port_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(0, 4);
                mach_port_t* port_array = new mach_port_t[port_count];  // Allocate array of ports

                for (uint32_t j = 0; j < port_count; j++) {
                    port_array[j] = create_mach_port_with_send_and_receive_rights();  // Create and store port
                }

                ool_ports_descriptor->address = port_array;
                ool_ports_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
                ool_ports_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
                ool_ports_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint8_t>(16, 26);
                ool_ports_descriptor->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
                ool_ports_descriptor->count = port_count;

                delete[] port_array;  // Ensure proper memory cleanup

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            default:
                break;
        }
    }
}


// Helper function to generate an OOL message
void generate_ool_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<uint8_t>& mach_msg, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    // HEADER
    std::vector<uint8_t> header;
    generate_header(fuzz_data, msg_size, msg_id, header, true);

    // DESCRIPTORS
    std::vector<uint8_t> descriptors;
    if (header.size() < msg_size) {
        generate_descriptors(fuzz_data, descriptors, descriptor_count, descriptor_types, ool_buffers);
    }

    // BODY
    std::vector<uint8_t> body;
    if (header.size() + descriptors.size() < msg_size) {
        uint32_t body_size = msg_size - (header.size() + descriptors.size());
        generate_body(msg_id, fuzz_data, body, body_size);
    }

    // Combine header, body, and descriptors. Resize if necessary
    mach_msg.insert(mach_msg.end(), header.begin(), header.end());
    mach_msg.insert(mach_msg.end(), descriptors.begin(), descriptors.end());
    mach_msg.insert(mach_msg.end(), body.begin(), body.end());
    // Will either trim if too long, or pad with zeroes
    mach_msg.resize(msg_size, 0);

    // TRAILER
    std::vector<uint8_t> trailer = get_standard_trailer();
    mach_msg.insert(mach_msg.end(), trailer.begin(), trailer.end());
}


void generate_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& mach_msg, std::vector<std::pair<void*, uint32_t>>& ool_buffers, bool is_ool_message) {
    switch (msg_id) {
        case XSystem_Open: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch condition to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x00;

            break;
        }
        case XObject_SetPropertyData_DCFString_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 31] = 0x1;

            // Read descriptor sizes from the message body
            uint32_t descriptor_size_0, descriptor_size_1;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));
            memcpy(&descriptor_size_1, &mach_msg[DESCRIPTOR_OFFSET_1], sizeof(uint32_t));

            descriptor_size_0 = descriptor_size_0 >> 1;
            descriptor_size_1 = descriptor_size_1 >> 1;

            // Now write these sizes to the last 8 bytes of the body
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 60], &descriptor_size_0, sizeof(uint32_t));  // Write descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 64], &descriptor_size_1, sizeof(uint32_t));  // Write descriptor_size_1

            break;
        }
        case XObject_SetPropertyData: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 31] = 0x1;

            // Read descriptor sizes from the message body
            uint32_t descriptor_size_0, descriptor_size_1;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));
            memcpy(&descriptor_size_1, &mach_msg[DESCRIPTOR_OFFSET_1], sizeof(uint32_t));

            // Now write these sizes to the last 8 bytes of the body
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 60], &descriptor_size_0, sizeof(uint32_t));  // Write descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 64], &descriptor_size_1, sizeof(uint32_t));  // Write descriptor_size_1

            break;
        }
        case XSystem_CreateIOContext: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Set the proper value to descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 28], &descriptor_size_0, sizeof(uint32_t));

            break;
        }
        case XIOContext_Start: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch condition to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XSystem_OpenWithBundleIDAndLinkage: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x54, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            break;
        }
        case XIOContext_StartAtTime_With_Shmem_SemaphoreTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x54, (uint32_t)0x03, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 26] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 38] = 0x11;

            break;
        }
        case XIOContext_StartAtTime_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XIOContext_StartAtTime: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmemAndTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndShmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        // FIXED (test-completed)
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupProperties: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        // FIXED (pending)
        case XSystem_CreateMetaDevice: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // To satisfy the condition, value_at_a1_39 must be 1
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = value_at_a1_39;

            // Condition 2: Get the value at a1 + 40 and set the same value at a1 + 52
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));

            // Set the value at a1 + 52 to be the same as a1 + 40
            memcpy(&mach_msg[52], &value_at_a1_40, sizeof(uint32_t));

            break;
        }
        // FIXED (pending)
        case XSystem_WriteSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Set the value at a1 + 39 to avoid *(unsigned __int8 *)(a1 + 39) << 24 != 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Set the value at a1 + 55 to avoid *(unsigned __int8 *)(a1 + 55) << 24 != 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Set the value at a1 + 68 to be half of the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            uint32_t value_at_a1_68 = value_at_a1_40 >> 1;
            memcpy(&mach_msg[68], &value_at_a1_68, sizeof(uint32_t));

            // Set the value at a1 + 72 to be the same as the value at a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            memcpy(&mach_msg[72], &value_at_a1_56, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DPList_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DPList_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XIOContext_SetClientControlPort: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_WorkInterval_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_Shmem_SemaphoreTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x03, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_WorkInterval: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XObject_SetPropertyData_DPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_SetPropertyData_DPList_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40 >> 1
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            uint32_t shifted_val = value_at_a1_40 >> 1;
            memcpy(&mach_msg[84], &shifted_val, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be  a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        // FIXED (tested)
        case XSystem_ReadSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Get the value at a1 + 40, (size) and set the value at a1 + 52 to be half of it
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));

            // Set the value at a1 + 52 to be half of a1 + 40
            uint32_t value_at_a1_52 = value_at_a1_40 >> 1;
            memcpy(&mach_msg[52], &value_at_a1_52, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleID: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_38 = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 38 - 24] = value_at_a1_38;

            // Condition 2: Ensure *(unsigned __int8 *)(a1 + 51) << 24 == 0x1000000
            uint8_t value_at_a1_51 = 0x01;
            mach_msg[MACH_MSG_HEADER_SIZE + 51 - 24] = value_at_a1_51;

            // Condition 3: Ensure (*(_DWORD *)(a1 + 52) >> 1) == *(_DWORD *)(a1 + 72)
            uint32_t value_at_a1_52;
            memcpy(&value_at_a1_52, &mach_msg[MACH_MSG_HEADER_SIZE + 52 - 24], sizeof(uint32_t));

            // Set the value at a1 + 72 to be half of the value at a1 + 52
            uint32_t value_at_a1_72 = value_at_a1_52 >> 1;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 72 - 24], &value_at_a1_72, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DI32_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) >> 1 == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 >> 1 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40 >> 1;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DCFString_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DPList_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DCFString_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }

        case XObject_GetPropertyData_DPList_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) != *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are not the same, adjust a1 + 68
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }

        case XSystem_OpenWithBundleIDLinkageAndKind: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 38 so that *(unsigned __int16 *)(a1 + 38) << 16 == 1114112
            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 38 - 24], &value_at_a1_38, sizeof(uint16_t));

            // Condition 2: Set the value at a1 + 51 so that *(unsigned __int8 *)(a1 + 51) << 24 == 0x1000000
            uint8_t value_at_a1_51 = 0x01;
            mach_msg[MACH_MSG_HEADER_SIZE + 51 - 24] = value_at_a1_51;

            // Condition 3: Ensure (*(_DWORD *)(a1 + 52) >> 1) == *(_DWORD *)(a1 + 80)
            uint32_t value_at_a1_52;
            memcpy(&value_at_a1_52, &mach_msg[MACH_MSG_HEADER_SIZE + 52 - 24], sizeof(uint32_t));

            // Set the value at a1 + 80 to be half of the value at a1 + 52
            uint32_t value_at_a1_80 = value_at_a1_52 >> 1;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 80 - 24], &value_at_a1_80, sizeof(uint32_t));

            break;
        }
        case XTransportManager_CreateDevice: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Set the proper value to descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 32], &descriptor_size_0, sizeof(uint32_t));

            break;
        }
        case XSystem_DeleteSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 28], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DPList_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DCFString_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DAI32_QAI32: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 2;  // Shift left by 2 

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DAI64_QAI64: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 3;  // Shift right by 3 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DAI32: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 2;  // Shift right by 2 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DAI64: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 3;  // Shift right by 2 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        // NORMAL MESSAGES
        case XSystem_Close: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x18, mach_msg);

            break;
        }
        case XSystem_DestroyIOContext: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XSystem_GetObjectInfo: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XSystem_DestroyMetaDevice: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFURL: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFString: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DI32_QI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFString_QI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DPList: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF32_QF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAI64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x38, mach_msg);

            break;
        }
        case XObject_AddPropertyListener: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_RemovePropertyListener: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XTransportManager_DestroyDevice: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x28, mach_msg);

            break;
        }
        case XIOContext_Fetch_Workgroup_Port: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_WaitForTap: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_StopWaitingForTap: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_Stop: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XObject_HasProperty: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_IsPropertySettable: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        default: {
            if (is_ool_message) {
                generate_ool_message(msg_id, fuzz_data, (uint32_t)0x00, (uint32_t)0x00, std::vector<mach_msg_descriptor_type_t>(), mach_msg, ool_buffers);
            } else {
                generate_normal_message(msg_id, fuzz_data, (uint32_t)0x00, mach_msg);
            }
            break;
        }    
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fuzz_data(data, size);

    bool first = true;

    while (fuzz_data.remaining_bytes() >= MACH_MSG_HEADER_SIZE) {
        verbose_print("\n*******NEW MESSAGE*******\n");

        // printf("Let it be known, the next ObjectID is: %llu\n", *NextObjectID);

        uint32_t msg_id;
        std::vector<std::pair<void*, uint32_t>> ool_buffers;
        std::vector<uint8_t> mach_msg;

        if (first) {
            msg_id = 1010000;
            first = false;
        } else {
            msg_id = fuzz_data.ConsumeIntegralInRange<uint32_t>(1010000, 1010072);
        }
        
        verbose_print("Message ID: %d (%s)\n", msg_id, message_id_to_string(static_cast<message_id_enum>(msg_id)));

        bool is_ool_message = ool_descriptor_set.find(static_cast<message_id_enum>(msg_id)) != ool_descriptor_set.end();

        // GENERATE MESSAGE
        generate_message(msg_id, fuzz_data, mach_msg, ool_buffers, is_ool_message);

        // Allocate memory for return buffer
        mach_msg_header_t *return_buffer = (mach_msg_header_t *)malloc(sizeof(mach_msg_header_t) + 10000); // Arbitrary at this point
        if (!return_buffer) {
            perror("Failed to allocate memory");
            for (const auto& buffer_pair : ool_buffers) {
                vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
            }
            exit(EXIT_FAILURE);
        }

        // Cast the buffer to mach_msg_header_t* for the function call
        mach_msg_header_t *fuzz_mach_msg = (mach_msg_header_t *)mach_msg.data();

        // fuzz_mach_msg->msgh_size = mach_msg_full_size - 52; // TRAILER_SIZE

        if (verbose) {
            printf("Sending the following mach msg:\n");
            print_mach_msg((mach_message *)fuzz_mach_msg, mach_msg.size(), true);
        }

        // Call the processing function
        uint64_t result = Mach_Processing_Function(fuzz_mach_msg, return_buffer);

        verbose_print("Processing function result: %llu\n", result);
        if (verbose) {
            // Print return message
            verbose_print("Return message:\n");
            print_mach_msg_no_trailer((mach_message*)return_buffer);
        }

        // Free the allocated memory
        free(return_buffer);
        // Deallocate all OOL buffers after the message is processed
        for (const auto& buffer_pair : ool_buffers) {
            vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
        }
    }

    return 0; // Non-crashing inputs should return 0
}

extern "C" int fuzz_shmem() {
    if (shm_data == NULL) {
        verbose_print("Error: Shared memory data pointer is NULL\n");
        return 1;
    }

    uint8_t *data = NULL;
    size_t size = 0;

    // Read the size from shared memory and check for validity
    size = (size_t)*(uint32_t *)(shm_data);
    if (size > MAX_SAMPLE_SIZE) {
        verbose_print("Warning: Size read from shared memory (%zu) exceeds MAX_SAMPLE_SIZE (%d). Truncating to MAX_SAMPLE_SIZE.\n", size, MAX_SAMPLE_SIZE);
        size = MAX_SAMPLE_SIZE;
    }

    // Allocate memory for data
    data = (uint8_t *)malloc(size);
    if (data == NULL) {
        verbose_print("Error: Failed to allocate memory for data of size %zu\n", size);
        return 1;
    }

    // Copy data from shared memory to the allocated buffer
    memcpy(data, shm_data + sizeof(uint32_t), size);
    verbose_print("Info: Successfully copied %zu bytes from shared memory to data buffer\n", size);

    // Pass the data to the fuzzer
    verbose_print("Info: Calling LLVMFuzzerTestOneInput with data size %zu\n", size);
    LLVMFuzzerTestOneInput((const uint8_t *)data, size);

    // Free the allocated memory
    free(data);
    verbose_print("Info: Freed allocated memory for data buffer\n");
    return 0;
}

extern "C" int fuzz(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening file");
        printf("Faulty file: %s", file_path);
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size > MAX_SAMPLE_SIZE) size = MAX_SAMPLE_SIZE;
    uint8_t *data = (uint8_t *)malloc(size);
    fread(data, 1, size, file);
    fclose(file);

    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}

int setup_shmem(char *name) {
    int fd;

    // get shared memory file descriptor (NOT a file)
    fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        perror("Error in shm_open\n");
        return 1;
    }

    // map shared memory to process address space
    shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (shm_data == MAP_FAILED)
    {
        printf("Error in mmap\n");
        return 1;
    }

    return 0;
}

#ifndef TEST_RUNNING
int main(int argc, char *argv[]) {
    char *shmem_name = NULL;
    char *file_path = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "m:f:vb")) != -1) {
        switch (opt) {
            case 'm':
                shmem_name = optarg;
                break;
            case 'f':
                file_path = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'b':
                print_bytes_only = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-m shmem_name] [-f file_path] [-v] [-b]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (file_path) {
        fuzz(file_path);
    } else if (shmem_name) {
        if (!setup_shmem(shmem_name)) {
            perror("Error mapping shared memory\n");
            return 1;
        }
        fuzz_shmem();
    } else {
        fprintf(stderr, "Usage: %s [-m shmem_name] [-f file_path] [-v] [-b]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
#endif

__attribute__((constructor()))
void constructor(void) {
    const char* wait_for_debugger = std::getenv("WAIT_FOR_DEBUGGER");

    if (wait_for_debugger && std::string(wait_for_debugger) == "1") {
        printf("Waiting for debugger to attach...\n");
        sleep(20);
        printf("Debugger attached, continuing execution...\n");
    }
    // const char *libraryPath = "/tmp/libraries/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio";
    const char * libraryPath = "/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio";
    const char *symbolName = "_HALB_MIGServer_server";

    if (!initAudioHardwareServer(libraryPath, "_AudioHardwareStartServer")) {
        printf("Failed to initialize AudioHardwareServer");
        exit(1);
    }
    if (!initMessageHandler(libraryPath, symbolName)) {
        printf("Failed to initialize MessageHandler\n");
        exit(1);
    }
    if (!initNextObjectId(libraryPath, "__ZN14HALS_ObjectMap13sNextObjectIDE")) {
        printf("Failed to initialize ObjectMap::sNextObjectId symbol\n");
        exit(1);
    }

    // Get the audit token for Safari
    safari_audit_token = get_safari_audit_token();

    // Check if the audit token is valid (non-zero)
    if (safari_audit_token.val[0] == 0 && safari_audit_token.val[1] == 0 &&
        safari_audit_token.val[2] == 0 && safari_audit_token.val[3] == 0 &&
        safari_audit_token.val[4] == 0 && safari_audit_token.val[5] == 0 &&
        safari_audit_token.val[6] == 0 && safari_audit_token.val[7] == 0) {
        printf("Failed to get audit token for Safari\n");
        exit(1);
    }

    //printf("Doin' a little swizzling ;)\n");
    setupSwizzling();
    
    //printf("Initializing Audio Hardware Server...\n");
    AudioHardwareStartServer();
    //printf("All ready to go!!\n");
}
