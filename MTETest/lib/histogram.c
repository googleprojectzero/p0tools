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

#include "histogram.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void histogram_reset(histogram_t* histogram) {
  memset(histogram->entries, 0, sizeof(histogram->entries));
  histogram->sorted = false;
}

static int histogram_compare(const void* lhs, const void* rhs) {
  uint64_t lhs_value = *(const uint64_t*)lhs;
  uint64_t rhs_value = *(const uint64_t*)rhs;
  if (lhs_value < rhs_value) {
    return -1;
  } else if (lhs_value == rhs_value) {
    return 0;
  } else {
    return 1;
  }
}

void histogram_sort(histogram_t* histogram) {
  if (!histogram->sorted) {
    qsort(histogram->entries, HISTOGRAM_SIZE - 1, sizeof(uint64_t),
          histogram_compare);
  }
  histogram->sorted = true;
}

uint64_t histogram_percentile(const histogram_t* histogram, unsigned percentile) {
  assert(histogram->sorted);
  return histogram->entries[(HISTOGRAM_SIZE * percentile) / 100];
}

size_t histogram_count(const histogram_t* histogram) {
  size_t count = 0;
  for (size_t i = 0; i < HISTOGRAM_SIZE; ++i) {
    if (histogram->entries[i] < histogram->threshold) {
      ++count;
    }
  }
  return count;
}

bool histogram_valid(const histogram_t* histogram) {
  size_t count = 0;
  for (size_t i = 0; i < HISTOGRAM_SIZE; ++i) {
    if (histogram->entries[i]) {
      ++count;
    }
  }
  return count == HISTOGRAM_SIZE;
}

void histogram_print(histogram_t* histogram, size_t scale) {
  size_t count = 0;
  for (size_t i = 0; i < HISTOGRAM_SIZE; ++i) {
    count += (histogram->entries[i] < histogram->threshold);
  }
  fprintf(stderr, "|");
  for (size_t i = 0; i < count / scale; ++i) {
    fprintf(stderr, "X");
  }
  for (size_t i = count / scale; i < HISTOGRAM_SIZE / scale; ++i) {
    fprintf(stderr, " ");
  }
  fprintf(stderr, "| %4zu", ((count * 100) / HISTOGRAM_SIZE));
}

void histogram_print_full(histogram_t* histogram) {
  for (size_t i = 0; i < HISTOGRAM_SIZE; ++i) {
    fprintf(stderr, "%zu: %lu\n", i, histogram->entries[i]);
  }
}
