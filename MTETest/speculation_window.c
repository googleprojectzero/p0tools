// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "lib/aarch64.h"
#include "lib/histogram.h"
#include "lib/mte.h"
#include "lib/perf_counters.h"
#include "lib/scheduler.h"
#include "lib/timer.h"

#define CODE_INSTRUCTIONS ((size_t)0x400)
#define CODE_SIZE (CODE_MAX_INSTRUCTIONS * sizeof(uint32_t))

__attribute__((aligned(0x1000)))
uint32_t code[CODE_INSTRUCTIONS];
uint32_t* code_ptr;

__attribute__((noinline))
void code_start(uint32_t nop_instruction) {
  mprotect(code, sizeof(code), PROT_READ|PROT_WRITE);
  for (size_t i = 0; i < CODE_INSTRUCTIONS; ++i) {
    code[i] = nop_instruction;
  }
  code_ptr = code;
}

__attribute__((noinline))
void code_emit(uint32_t instruction) {
  *code_ptr = instruction;
  code_ptr += 1;
}

__attribute__((noinline))
void code_skip(size_t count) {
  code_ptr += count;
}

__attribute__((noinline))
void code_finish() {
  mprotect(code, sizeof(code), PROT_READ|PROT_EXEC);
  flush_instruction_cache(code, sizeof(code));
}

const uint32_t cbnz_x0_c    = 0xb5000060;
const uint32_t ldr_x0_x0    = 0xf9400000;
const uint32_t ldr_x1_x1    = 0xf9400021;
const uint32_t ldr_x2_x2    = 0xf9400042;
const uint32_t orr_x1_x2_x1 = 0xaa010041;
const uint32_t ret          = 0xd65f03c0;
const uint32_t bkpt         = 0xd4200000;

typedef void (*function)(void*, void*, void*);
const function code_function = (void(*)(void*,void*,void*))(code);

__attribute__((noinline))
void generate_code(size_t nop_count) {
  // Generate our test code

  // Ideally we would offset the loads to prevent kernel noise from having those
  // pointers sitting around in registers, but they anyway need to be there for
  // the cache flushes, so there's not much point.

  code_start(orr_x1_x2_x1);
  code_emit(ldr_x0_x0);      // slow load
  code_emit(cbnz_x0_c);      // branch based on loaded value
  code_emit(ret);            //   -> correct branch = return
  code_emit(bkpt);           // stop straight-line speculation
                             //   -> incorrect branch
  code_emit(ldr_x1_x1);      // fast load from tagged memory
  code_skip(nop_count);      // avoid a branch here based on nop_count
  //for (size_t i = 0; i < nop_count; ++i) {
  //  code_emit(orr_x1_x2_x1); // nops that propagate data dependency on x1
  //}
  code_emit(ldr_x2_x2);      // load from timing_ptr_1
  code_emit(ret);
  code_emit(bkpt);
  code_finish();
}

__attribute__((noinline))
void* map_and_zero(size_t size, bool tagged) {
  int prot = PROT_READ|PROT_WRITE;
  if (tagged) {
    prot |= PROT_MTE;
  }
  uint64_t* ptr = (uint64_t*)mmap(NULL, size, prot,
    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (tagged) {
    ptr = mte_tag_and_zero(ptr, size);
  } else {
    memset(ptr, 0, size);
  }
  return ptr;
}

uint64_t prng_state = 0;
uint32_t prng_counter = 0;

__attribute__((noinline))
uint32_t prng() {
  prng_state ^= prng_state >> 12;
  prng_state ^= prng_state << 25;
  prng_state ^= prng_state >> 27;
  prng_counter += 362437;
  // xorshift may have some patterns in the low bits, we don't need many bits of
  // randomness here anyway, so take the high bits only.
  return (prng_state + prng_counter) >> 32;
}

void run_tests(int cpu, size_t iterations, size_t start_count, size_t end_count) {
  uint64_t* slow_ptr = (uint64_t*)(char*)map_and_zero(0x20000, false);
  uint64_t* timing_ptr = (uint64_t*)(char*)map_and_zero(0x20000, false);
  uint64_t* right_tag_ptr = map_and_zero(0x20000, true);

  for (size_t i = 0; i < iterations; ++i) {
    right_tag_ptr = mte_tag_and_zero(right_tag_ptr, 0x20000);

    uint32_t random = prng();
    size_t nop_count = start_count + (((random << 1) >> 1) % (end_count - start_count));
    bool pass = random >> 31;
    generate_code(nop_count);

    uint64_t latency = 0;

    // [1] BRANCH_PREDICTOR_ITERATIONS branches
    for (uint64_t j = 0; j < BRANCH_PREDICTOR_ITERATIONS; ++j) {
      // Only the last iteration is not a warmup. This needs to compile
      // branch-free...
      uint64_t is_warmup = ((j + 1) ^ BRANCH_PREDICTOR_ITERATIONS) != 0;
      *slow_ptr = is_warmup + *right_tag_ptr;

      // On the last iteration we might be clearing the tag bit, if we're
      // supposed to be failing the tag check. This also needs to compile
      // branch-free...
      uintptr_t ptr_mask = 0xfffffffffffffffful
                           ^ (!pass * !is_warmup * 0xff00000000000000ul);
      uint64_t* tag_ptr = (uint64_t*)((uintptr_t)right_tag_ptr & ptr_mask);

      // We want `slow_ptr` and `timing_ptr` to be uncached, and
      // `right_tag_ptr` to be cached.
      local_memory_barrier();
      flush_data_cache(slow_ptr);
      flush_data_cache(timing_ptr);
      local_memory_barrier();
      instruction_barrier();

      // [2] BRANCH_PREDICTOR_ITERATIONS branches
      code_function(slow_ptr, tag_ptr, timing_ptr);

      latency = read_latency(timing_ptr);
    }

    printf("%i,%i,%zu,%zu\n", cpu, pass, nop_count, latency);
  }
}

int main(int argc, char** argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: speculation_window cpu_id seed iterations start_count end_count\n");
    exit(-1);
  }

  int cpu = atoi(argv[1]);
  size_t seed = atoi(argv[2]);
  size_t iterations = atoi(argv[3]);
  size_t start_count = atoi(argv[4]);
  size_t end_count = atoi(argv[5]);

  prng_state = seed;

  set_max_priority();
  start_timer();

  mte_enable(false, DEFAULT_TAG_MASK);
  cpu_pin_to(cpu);

  run_tests(cpu, iterations, start_count, end_count);
}