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

#include "perf_counters.h"

#include <stdio.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "config.h"
#include "scheduler.h"

perf_t read_perf_counters() {
  static int fds[5] = {0};
  static perf_t value = {0};

  if (!fds[0]) {
    int cpu_id = cpu_currently_on();
    struct perf_event_attr event_attr = {0};
    event_attr.type = PERF_TYPE_HARDWARE;
    event_attr.size = sizeof(event_attr);
    event_attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    fds[0] = syscall(SYS_perf_event_open, &event_attr, 0, cpu_id, -1, PERF_FLAG_FD_NO_GROUP);
    event_attr.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    fds[1] = syscall(SYS_perf_event_open, &event_attr, 0, cpu_id, -1, PERF_FLAG_FD_NO_GROUP);
    event_attr.config = PERF_COUNT_HW_BRANCH_MISSES;
    fds[2] = syscall(SYS_perf_event_open, &event_attr, 0, cpu_id, -1, PERF_FLAG_FD_NO_GROUP);
    event_attr.config = PERF_COUNT_HW_CACHE_REFERENCES;
    fds[3] = syscall(SYS_perf_event_open, &event_attr, 0, cpu_id, -1, PERF_FLAG_FD_NO_GROUP);
    event_attr.config = PERF_COUNT_HW_CACHE_MISSES;
    fds[4] = syscall(SYS_perf_event_open, &event_attr, 0, cpu_id, -1, PERF_FLAG_FD_NO_GROUP);
  }

  perf_t prev_value = value;
  read(fds[0], &value.instructions, sizeof(value.instructions));
  read(fds[1], &value.branch_instructions, sizeof(value.branch_instructions));
  read(fds[2], &value.branch_misses, sizeof(value.branch_misses));
  read(fds[3], &value.cache_references, sizeof(value.cache_references));
  read(fds[4], &value.cache_misses, sizeof(value.cache_misses));

  perf_t return_value = value;
  return_value.instructions -= prev_value.instructions;
  return_value.branch_instructions -= prev_value.branch_instructions;
  return_value.branch_misses -= prev_value.branch_misses;
  return_value.cache_references -= prev_value.cache_references;
  return_value.cache_misses -= prev_value.cache_misses;

  return return_value;
}

void print_scaled_perf_counters(perf_t value, uint64_t scale) {
  value.instructions /= scale;
  value.branch_misses /= scale;
  value.branch_instructions /= scale;
  value.cache_misses /= scale;
  value.cache_references /= scale;

  fprintf(stderr, "i %10lu b %10lu/%10lu [%1.1f%%] c %10lu/%10lu [%1.1f%%]\n",
    value.instructions,
    value.branch_misses, value.branch_instructions,
    (double)value.branch_misses / (double)value.branch_instructions,
    value.cache_misses, value.cache_references,
    (double)value.cache_misses / (double)value.cache_references);
}
