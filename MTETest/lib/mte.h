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

#ifndef MTE_H_
#define MTE_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define DEFAULT_TAG_MASK ((uint16_t)0xfffe)

void mte_enable(bool sync, uint16_t tag_mask);
void mte_disable();

__attribute__((always_inline))
inline void* mte_tag_and_zero(void* ptr, size_t len) {
  asm volatile ("irg %0, %0\n" : "+r"(ptr));
  void* end_ptr = ptr;
  for (size_t i = 0; i < len; i += 16) {
    asm volatile ("stzg %0, [%0], #16\n" : "+r"(end_ptr));
  }
  return ptr;
}

__attribute__((always_inline))
inline void* mte_tag(void* ptr, size_t len) {
  asm volatile ("irg %0, %0\n" : "+r"(ptr));
  void* end_ptr = ptr;
  for (size_t i = 0; i < len; i += 16) {
    asm volatile ("stg %0, [%0], #16\n" : "+r"(end_ptr));
  }
  return ptr;
}

__attribute__((always_inline))
inline void* mte_strip_tag(void* ptr) {
  return (uint64_t*)((uintptr_t)ptr & 0xfffffffffffffful);
}

#endif // MTE_H_
