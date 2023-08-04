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

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  mte_enable(false, DEFAULT_TAG_MASK);
  uint64_t* ptr = mmap(NULL, 0x1000,
    PROT_READ|PROT_WRITE|PROT_MTE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  uint64_t* tagged_ptr = mte_tag_and_zero(ptr, 0x1000);
  // In async MTE mode, the kernel does not catch invalid accesses to userspace
  // pointers. This is documented behaviour:
  // https://elixir.bootlin.com/linux/v5.18.9/source/Documentation/arm64/memory-tagging-extension.rst#L111
  memset(tagged_ptr, 0x23, 0x1000);
  int fd = open("/dev/urandom", O_RDONLY);
  fprintf(stderr, "%p %p\n", ptr, tagged_ptr);
  read(fd, ptr, 0x1000);
  assert(*tagged_ptr == 0x2323232323232323ull);
}
