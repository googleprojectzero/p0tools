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

#ifndef HARNESS_H
#define HARNESS_H

#include <mach/mach.h>
#include <fuzzer/FuzzedDataProvider.h>

typedef struct {
    mach_msg_header_t header;
    char body[];
} mach_message;

typedef struct {
    mach_msg_header_t header;
    mach_msg_size_t descriptor_count;
    mach_msg_type_descriptor_t descriptors[];
} descriptor_mach_message;

#include "debug.h"
#include "initialization.h"
#include "audit_token.h"
#include "message.h"

#include <stdio.h>
#include <stdlib.h>

#define MAX_SAMPLE_SIZE 10000
#define MAX_MESSAGE_SIZE 1000
#define MAX_MACH_MSG_TRAILER_SIZE 1000
#define MACH_MSG_TRAILER_HEADER_SIZE 20
#define MACH_MSG_TRAILER_SIZE 52
#define MACH_MSG_HEADER_SIZE 24
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE) 
#define MAX_OOL_DATA_SIZE (1 * 1024) // 1MB

const size_t DESCRIPTOR_OFFSET_0 = MACH_MSG_HEADER_SIZE + sizeof(uint32_t) + 12;
const size_t DESCRIPTOR_OFFSET_1 = MACH_MSG_HEADER_SIZE + sizeof(uint32_t) + sizeof(mach_msg_ool_descriptor_t) + 12;

// Global variables
extern unsigned char *shm_data;
extern int verbose;
extern int print_bytes_only;

// Function prototypes and typedefs
typedef uint64_t (*t_Mach_Processing_Function)(mach_msg_header_t *incoming_mach_msg, mach_msg_header_t *returning_mach_msg);
extern t_Mach_Processing_Function Mach_Processing_Function;

typedef void (*t_AudioHardwareStartServer)(void);
extern t_AudioHardwareStartServer AudioHardwareStartServer;

extern uint64_t *NextObjectID;

void generate_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& mach_msg, std::vector<std::pair<void*, uint32_t>>& ool_buffers, bool is_ool_message);

// Audit token for Safari
extern audit_token_t safari_audit_token;

#endif // HARNESS_H