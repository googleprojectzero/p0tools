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

#ifndef AARCH64_H_
#define AARCH64_H_

#define CACHE_LINE_SIZE ((size_t)64)

__attribute__((always_inline))
inline void instruction_barrier() {
  asm volatile ("isb");
}

__attribute__((always_inline))
inline void system_memory_barrier() {
  asm volatile ("dsb sy":::"memory");
}

__attribute__((always_inline))
inline void local_memory_barrier() {
  asm volatile ("dsb ish":::"memory");
}

__attribute__((always_inline))
inline void flush_data_cache(void* ptr) {
  asm volatile ("dc civac, %0"::"r"(ptr):"memory");
}

__attribute__((always_inline))
inline void flush_instruction_cache(void* ptr, size_t size) {
  char* char_ptr = ptr;
  for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
    asm volatile ("dc cvau, %0"::"r"(char_ptr + i):"memory");
  }
  local_memory_barrier();
  for (size_t i = 0; i < size; i += CACHE_LINE_SIZE) {
    asm volatile ("ic ivau, %0"::"r"(char_ptr + i):"memory");
  }
  local_memory_barrier();
  instruction_barrier();
}

__attribute__((always_inline))
inline uint64_t virtual_count() {
  uint64_t count;
  asm volatile ("mrs %0, cntvct_el0\n":"=r"(count)::);
  return count;
}

#endif // AARCH64_H_
