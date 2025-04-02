#ifndef MACH_HELPERS_H
#define MACH_HELPERS_H

#include "harness.h"
#include <dlfcn.h>
#include <mach-o/loader.h>

void *LoadLibrary(const char *name);
void *GetLoadCommand(struct mach_header_64 *mach_header, void *load_commands_buffer, uint32_t load_cmd_type, const char *segname);
void *GetSymbolAddress(void *base_address, const char *symbol_name);

#endif