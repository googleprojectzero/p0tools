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

#include <mach/mach.h>
#include <stdarg.h>

// Forward declarations
int sandbox_check(int pid, const char *operation, int type, ...);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service_name, mach_port_t *service_port);

// Custom implementations
kern_return_t custom_mach_port_deallocate(ipc_space_t task, mach_port_name_t name) {
    return KERN_SUCCESS;
}

kern_return_t custom_mach_port_mod_refs(ipc_space_t task, mach_port_name_t name, mach_port_right_t right, mach_port_delta_t delta) {
    return KERN_SUCCESS;
}

int custom_sandbox_check(int pid, const char *operation, int type, ...) {
    return KERN_SUCCESS;
}

kern_return_t custom_bootstrap_check_in(mach_port_t bootstrap_port, const char *service_name, mach_port_t *service_port) {
    // Ensure service_port is non-null and set it to a non-zero value
    if (service_port) {
        *service_port = 1;  // Set to a non-zero value
    }

    return KERN_SUCCESS;  // Return 0 (KERN_SUCCESS) to avoid triggering the `jnz`
}

// Custom implementation of mach_port_insert_right
kern_return_t custom_mach_port_insert_right(ipc_space_t task, mach_port_name_t name, mach_port_t poly, mach_msg_type_name_t polyPoly) {
    return KERN_SUCCESS;  // Always return KERN_SUCCESS
}

// Interposing array
__attribute__((used)) static struct {
    const void* replacement;
    const void* replacee;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)custom_mach_port_deallocate, (const void *)mach_port_deallocate },
    { (const void *)custom_mach_port_mod_refs, (const void *)mach_port_mod_refs },
    { (const void *)custom_sandbox_check, (const void *)sandbox_check },
    { (const void *)custom_bootstrap_check_in, (const void *)bootstrap_check_in },
    { (const void *)custom_mach_port_insert_right, (const void *)mach_port_insert_right }
};
