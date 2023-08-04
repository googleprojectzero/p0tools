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

#ifndef PERF_COUNTERS_H_
#define PERF_COUNTERS_H_

#include "../config.h"

typedef struct {
  uint64_t instructions;
  uint64_t branch_instructions;
  uint64_t branch_misses;
  uint64_t cache_references;
  uint64_t cache_misses;
} perf_t;

perf_t read_perf_counters();
void print_scaled_perf_counters(perf_t value, uint64_t scale);

#endif // PERF_COUNTERS_H_