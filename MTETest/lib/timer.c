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

#include "scheduler.h"
#include "timer.h"

#if TIMER == VIRTUAL_TIMER
void start_timer() {
}
#elif TIMER == SHARED_MEMORY_TIMER
#include <pthread.h>

volatile uint64_t shared_counter = 0;
pthread_t shared_memory_timer_thread;

static void* shared_memory_timer_func(void* ignored) {
  cpu_pin_to(SHARED_MEMORY_TIMER_CPU);

  while (true) {
    ++shared_counter;
  }

  return NULL;
}

void start_timer() {
  pthread_create(&shared_memory_timer_thread, NULL, &shared_memory_timer_func, NULL);
  while (!shared_counter) {}
}
#endif
