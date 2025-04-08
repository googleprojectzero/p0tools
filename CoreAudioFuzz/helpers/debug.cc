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

#include "debug.h"

void verbose_print(const char *format, ...) {
    if (verbose) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

void print_mach_msg(mach_message *msg, size_t total_size, bool is_ool_message) {
    (void)is_ool_message;
    printf("------ MACH MSG HEADER ------\n");
    printf("msg_bits: %u\n", msg->header.msgh_bits);
    printf("msg_size: %u\n", msg->header.msgh_size);
    printf("msg_remote_port: %u\n", msg->header.msgh_remote_port);
    printf("msg_local_port: %u\n", msg->header.msgh_local_port);
    printf("msg_voucher_port: %u\n", msg->header.msgh_voucher_port);
    printf("msg_id: %u\n", msg->header.msgh_id);

    size_t header_size = sizeof(mach_msg_header_t);
    size_t msg_body_size = msg->header.msgh_size - header_size;
    printf("------ MACH MSG BODY (%lu bytes) ------\n", msg_body_size);

    for (size_t i = 0; i < msg_body_size; i++) {
        printf("0x%02x ", (unsigned char)msg->body[i]);
    }
    printf("\n");

    // Calculate and print trailer if present
    size_t trailer_size = total_size - msg->header.msgh_size;
    if (trailer_size >= MACH_MSG_TRAILER_SIZE) {
        printf("------ MACH MSG TRAILER ------\n");
        uint8_t *trailer = (uint8_t *)(msg->body + msg_body_size);
        printf("msg_trailer_type: %u\n", *(uint32_t *)(trailer));
        uint32_t trailer_body_size = *(uint32_t *)(trailer + 4);
        printf("msg_trailer_size: %u\n", trailer_body_size);
        printf("msg_seqno: %u\n", *(uint32_t *)(trailer + 8));
        printf("msg_sender: %llu\n", *(uint64_t *)(trailer + 12));

        printf("------ MACH MSG TRAILER BODY (%u bytes) ------\n", trailer_body_size);
        for (size_t i = 0; i < trailer_body_size; i++) {
            printf("0x%02x ", trailer[MACH_MSG_TRAILER_HEADER_SIZE + i]);
        }
        printf("\n");
    }

    // Append the full mach message in bytes if -b flag is set
    if (print_bytes_only) {
        printf("\n------ FULL MESSAGE IN BYTES ------\n");
        uint8_t *full_msg = (uint8_t *)msg;  // Pointer to the full message
        for (size_t i = 0; i < total_size; i++) {
            printf("0x%02x ", full_msg[i]);
        }
        printf("\n");
    }
}

void print_mach_msg_no_trailer(mach_message *msg) {
    printf("------ MACH MSG HEADER ------\n");
    printf("msg_bits: %u\n", msg->header.msgh_bits);
    printf("msg_size: %u\n", msg->header.msgh_size);
    printf("msg_remote_port: %u\n", msg->header.msgh_remote_port);
    printf("msg_local_port: %u\n", msg->header.msgh_local_port);
    printf("msg_voucher_port: %u\n", msg->header.msgh_voucher_port);
    printf("msg_id: %u\n", msg->header.msgh_id);

    size_t header_size = sizeof(mach_msg_header_t);
    size_t msg_body_size = msg->header.msgh_size - header_size;
    printf("------ MACH MSG BODY (%lu bytes) ------\n", msg_body_size);

    for (size_t i = 0; i < msg_body_size; i++) {
        printf("0x%02x ", (unsigned char)msg->body[i]);
    }
    printf("\n");
}
