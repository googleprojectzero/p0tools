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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "lib/mte.h"

#define DEFAULT_TAG_MASK ((uint16_t)0xfffe)

void* _mte_tag(void* ptr, size_t len) {
  asm volatile ("irg %0, %0\n" : "+r"(ptr));
  void* end_ptr = ptr;
  for (size_t i = 0; i < len; i += 16) {
    asm volatile ("stg %0, [%0], #16\n" : "+r"(end_ptr));
  }
  return ptr;
}

size_t readn(int fd, void* ptr, size_t len) {
  char* start_ptr = ptr;
  char* read_ptr = ptr;
  while (read_ptr < start_ptr + len) {
    ssize_t result = read(fd, read_ptr, start_ptr + len - read_ptr);
    if (result <= 0) {
      return read_ptr - start_ptr;
    } else {
      read_ptr += result;
    }
  }
  return len;
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  mte_enable(true, DEFAULT_TAG_MASK);
  char* ptr = mmap(NULL, 0x1000,
    PROT_READ|PROT_WRITE|PROT_MTE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  ptr = _mte_tag(ptr, 0x10);
  strcpy(ptr, "AAAAAAAAAAAAAAA");

  int pipefd[2];
  assert(!pipe(pipefd));
  write(pipefd[1], "BBBBBBBBBBBBBBB", 0x10);

  // In sync MTE mode, kernel MTE tag-check failures cause system calls to fail
  // with EFAULT rather than triggering a SIGSEGV. Existing code doesn't
  // generally expect to receive EFAULT, and is very unlikely to handle it as a
  // critical error.

  char* new_ptr = ptr;
  while (!strcmp(new_ptr, "AAAAAAAAAAAAAAA")) {
    // Simulate a use-after-free, where new_ptr is repeatedly free'd and ptr
    // is accessed after the free via a syscall.
    new_ptr = _mte_tag(new_ptr, 0x10);
    strcpy(new_ptr, "AAAAAAAAAAAAAAA");

    // The use of ptr in the next statement is modelling a use-after-free.
    size_t bytes_read = readn(pipefd[0], ptr, 0x10);
    fprintf(stderr, "read %zu bytes\nnew_ptr string is %s\n", bytes_read, new_ptr);

    if (ptr == new_ptr) {
      break;
    }
  }
}
