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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <malloc.h>

#include "lib/mte.h"
#include "lib/scheduler.h"

#include "duktape.h"

static void* read_file(const char* path) {
  int fd = open(path, O_RDONLY);
  size_t data_read = 0;
  size_t data_size = 0;
  char* data = NULL;
  while (true) {
    if (data_read == data_size) {
      char* new_data = realloc(data, data_size + 1024);
      if (!new_data) {
        free(data);
        return NULL;
      }
      data = new_data;
      data_size = data_size + 1024;
    }
    ssize_t result = read(fd, &data[data_read], data_size - data_read);
    if (result <= 0) {
      return data;
    } else {
      data_read += result;
    }
  }
}

static duk_ret_t print(duk_context *ctx) {
  fprintf(stderr, "%s\n", duk_to_string(ctx, 0));
  return 0;
}

static duk_ret_t corrupt_bytearray(duk_context* ctx) {
  if (duk_get_type(ctx, 0) == DUK_TYPE_OBJECT) {
    uint32_t* bufobj_i = duk_get_heapptr(ctx, 0);
    uint32_t** bufobj_p = (uint32_t**)bufobj_i;
    // Set the ArrayBuffer byteLength
    bufobj_i[19] = 0xffffffff;
    // Set the backing store size
    bufobj_p[7][6] = 0xffffffff;
  }
  return 0;
}

static duk_ret_t tag_check_fail(duk_context* ctx) {
  (void)ctx;
  void* ptr = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_MTE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  mte_tag_and_zero(ptr, 0x1000);
  *(char*)ptr = 0x23;
  return 0;
}

// This is a very rough simulation of the Breakpad exception handling code for
// linux, see:
// https://source.chromium.org/chromium/chromium/src/+/main:third_party/breakpad/breakpad/src/client/linux/handler/exception_handler.cc;l=328
bool (*g_first_chance_handler)(int signal, siginfo_t* info, void* ucontext_ptr) = NULL;
void segv_handler(int signal, siginfo_t* info, void* ucontext_ptr) {
  fprintf(stderr, "segv handler %i\n", signal);
  if (g_first_chance_handler && g_first_chance_handler(signal, info, ucontext_ptr)) {
    return;
  }
  fprintf(stderr, "killing process\n");
  exit(1);
}

void add_segv_handler() {
  struct sigaction new_segv_handler, old_segv_handler;
  new_segv_handler.sa_sigaction = segv_handler;
  new_segv_handler.sa_flags = SA_SIGINFO;
  assert(0 == sigaction(SIGSEGV, &new_segv_handler, &old_segv_handler));
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: async_signal_handler_bypass exploit_javascript\n");
    exit(-1);
  }

  g_first_chance_handler = NULL;
  add_segv_handler();

  mte_enable(false, DEFAULT_TAG_MASK);

  // We have the hosting code compute necessary offsets here and provide those
  // to the exploit code to avoid having to manually generate offsets when
  // building...
  uint32_t* elf_base_ptr = (uint32_t*)(((uintptr_t)print) - 0x20000);
  while (*elf_base_ptr != 0x464c457f)
    --elf_base_ptr;

  char* offsets;
  asprintf(&offsets,
           "var print_offset = %p;\n"
           "var first_chance_handler_offset = %p;\n",
           (void*)((uintptr_t)print - (uintptr_t)elf_base_ptr),
           (void*)((uintptr_t)&g_first_chance_handler - (uintptr_t)elf_base_ptr));

  char* script = read_file(argv[1]);

  char* full_script;
  asprintf(&full_script, "%s\n%s", offsets, script);

  duk_context *ctx = duk_create_heap_default();

  duk_push_c_function(ctx, print, 1);
  duk_put_global_string(ctx, "print");

  duk_push_c_function(ctx, tag_check_fail, 0);
  duk_put_global_string(ctx, "tag_check_fail");

  duk_push_c_function(ctx, corrupt_bytearray, 1);
  duk_put_global_string(ctx, "corrupt_bytearray");

  duk_eval_string_noresult(ctx, full_script);
  duk_destroy_heap(ctx);

  fprintf(stderr, "done\n");

  return 0;
}