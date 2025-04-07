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

#ifndef MACH_HELPERS_H
#define MACH_HELPERS_H

#include "harness.h"
#include <dlfcn.h>
#include <mach-o/loader.h>

void *LoadLibrary(const char *name);
void *GetLoadCommand(struct mach_header_64 *mach_header, void *load_commands_buffer, uint32_t load_cmd_type, const char *segname);
void *GetSymbolAddress(void *base_address, const char *symbol_name);

#endif