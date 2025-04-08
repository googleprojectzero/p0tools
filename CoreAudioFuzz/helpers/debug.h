/* 
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef DEBUG_H
#define DEBUG_H

#include "harness.h" 
#include <stdarg.h>
#include <stddef.h>

void verbose_print(const char *format, ...);
void print_mach_msg(mach_message *msg, size_t total_size, bool is_ool_message);
void print_mach_msg_no_trailer(mach_message *msg);

#endif // DEBUG_H#