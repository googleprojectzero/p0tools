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

#ifndef CONFIG_H_
#define CONFIG_H_

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Histogram configuration
#define HISTOGRAM_SIZE ((size_t)100)
#define HISTOGRAM_SCALE (4)

// Timing configuration
#define VIRTUAL_TIMER 0
#define SHARED_MEMORY_TIMER 1
#define TIMER VIRTUAL_TIMER

#if TIMER == SHARED_MEMORY_TIMER
// CPU core to use for running the shared memory timer thread. This should not
// collide with the core being tested!
#define SHARED_MEMORY_TIMER_CPU 1
// This should be calculated for the CPU under test using calibrate_timer
#endif

// This may need adjusting depending on the branch predictor behaviour of the
// CPU you are using.
#define BRANCH_PREDICTOR_ITERATIONS (512)

// Print histograms to visualize the results of each testcase.
//#define PRINT_HISTOGRAM

// Print performance counter information to help with debugging branch predictor
// behaviour.
//#define PRINT_COUNTERS

#endif // CONFIG_H_
