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

#ifndef HISTOGRAM_H_
#define HISTOGRAM_H_

#include "config.h"

// Statically allocated histogram type - we use these rather than dynamically
// allocated arrays so that we can encourage the compiler to generate very
// simple code in the hot-paths. We also add an extra (unused) element at the
// end of the entries, since we need a branch-free way to ignore an entry in the
// histogram.
//
// This is not intended for general purpose use...

typedef struct {
  uint64_t entries[HISTOGRAM_SIZE + 1];
  uint64_t threshold;
  bool sorted;
} histogram_t;

void histogram_reset(histogram_t* histogram);
void histogram_sort(histogram_t* histogram);
uint64_t histogram_percentile(const histogram_t* histogram, unsigned percentile);
size_t histogram_count(const histogram_t* histogram);
bool histogram_valid(const histogram_t* histogram);
void histogram_print(histogram_t* histogram, size_t scale);
void histogram_print_full(histogram_t* histogram);

#endif // HISTOGRAM_H_
