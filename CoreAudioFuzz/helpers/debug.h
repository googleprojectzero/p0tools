#ifndef DEBUG_H
#define DEBUG_H

#include "harness.h" 
#include <stdarg.h>
#include <stddef.h>

void verbose_print(const char *format, ...);
void print_mach_msg(mach_message *msg, size_t total_size, bool is_ool_message);
void print_mach_msg_no_trailer(mach_message *msg);

#endif // DEBUG_H#