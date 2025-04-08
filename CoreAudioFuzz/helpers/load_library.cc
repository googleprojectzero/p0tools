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

#include "load_library.h"
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>

// loads the library and gets its base address
void *LoadLibrary(const char *name) {
    dlopen(name, RTLD_LAZY);

    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    kern_return_t krt;
    krt = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    if (krt != KERN_SUCCESS) {
        printf("Unable to retrieve task_info, %d\n", krt);
        return NULL;
    }
    struct dyld_all_image_infos *all_image_infos = (struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
    const struct dyld_image_info *all_image_info_array = all_image_infos->infoArray;

    for (uint32_t i = 0; i < all_image_infos->infoArrayCount; ++i) {
        if(strcmp(all_image_info_array[i].imageFilePath, name) == 0) {
            return (void*)all_image_info_array[i].imageLoadAddress;
        }
    }

    return NULL;
}

void *GetLoadCommand(struct mach_header_64 *mach_header,
                              void *load_commands_buffer,
                              uint32_t load_cmd_type,
                              const char *segname) {
    uint64_t load_cmd_addr = (uint64_t)load_commands_buffer;
    for (uint32_t i = 0; i < mach_header->ncmds; ++i) {
        struct load_command *load_cmd = (struct load_command *)load_cmd_addr;
        if (load_cmd->cmd == load_cmd_type) {
            if (load_cmd_type != LC_SEGMENT_64 || !strcmp(((struct segment_command_64*)load_cmd)->segname, segname)) {
            return load_cmd;
            }
        }
        load_cmd_addr += load_cmd->cmdsize;
    }

return NULL;
}

void *GetSymbolAddress(void *base_address, const char *symbol_name) {
    struct mach_header_64 *mach_header = (struct mach_header_64 *)base_address;

    void *load_commands_buffer = (void *)((uint64_t)base_address + sizeof(struct mach_header_64));

    struct symtab_command *symtab_cmd = (struct symtab_command *)GetLoadCommand(mach_header, load_commands_buffer, LC_SYMTAB, NULL);

    struct segment_command_64 *linkedit_cmd = (struct segment_command_64 *)GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__LINKEDIT");

    struct segment_command_64 *text_cmd = (struct segment_command_64 *)GetLoadCommand(mach_header, load_commands_buffer, LC_SEGMENT_64, "__TEXT");

    uint64_t file_vm_slide = (uint64_t)base_address - text_cmd->vmaddr;

    char *strtab = (char *)linkedit_cmd->vmaddr + file_vm_slide
                    + symtab_cmd->stroff - linkedit_cmd->fileoff;

    char *symtab = (char *)(linkedit_cmd->vmaddr + file_vm_slide
                    + symtab_cmd->symoff - linkedit_cmd->fileoff);

    void *symbol_address = NULL;

    size_t curr_symbol_address = (size_t)symtab;

    for (int i = 0; i < (int)symtab_cmd->nsyms; ++i) {
        struct nlist_64 curr_symbol = *(struct nlist_64*)curr_symbol_address;
        if ((curr_symbol.n_type & N_TYPE) == N_SECT) {
            char *curr_sym_name = NULL;
            curr_sym_name = strtab + curr_symbol.n_un.n_strx;

            //printf("%s\n", curr_sym_name);
            if (!strcmp(curr_sym_name, symbol_name)) {
                symbol_address = (void*)((uint64_t)base_address - text_cmd->vmaddr + curr_symbol.n_value);
                break;
            }
        }

        curr_symbol_address += sizeof(struct nlist_64);
    }

  return symbol_address;
}