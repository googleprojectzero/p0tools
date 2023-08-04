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

#include "config.h"

#include <assert.h>
#include <string.h>

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

void cpu_pin_to(int core) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(core, &cpu_set);
  assert(-1 != sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set));
}

int cpu_currently_on() {
  unsigned int cpu = 0, node = 0;
  assert(0 <= getcpu(&cpu, &node));
  return cpu;
}

void set_max_priority() {
  setpriority(PRIO_PROCESS, 0, -20);
}