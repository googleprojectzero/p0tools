/*
Copyright 2024 Google LLC

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>

#include "loader.h"

std::unordered_map<std::string, uint64_t> symbol_table;

uint32_t BREAKPOINT = 0xd4200000;

#define SEGMENT_READ 4
#define SEGMENT_WRITE 2
#define SEGMENT_EXEC 1

#define TINYINST_REGISTER_REPLACEMENT 0x747265706C616365
#define TINYINST_CUSTOM_INSTRUMENT 0x747265706C616366

typedef void (*t_tinyinst_register_replacement)(uint64_t, uint64_t);
t_tinyinst_register_replacement tinyinst_register_replacement = (t_tinyinst_register_replacement)TINYINST_REGISTER_REPLACEMENT;

typedef void (*t_tinyinst_instrument_range)(uint64_t, uint64_t);
t_tinyinst_instrument_range tinyinst_instrument_range = (t_tinyinst_register_replacement)TINYINST_CUSTOM_INSTRUMENT;

struct Segment {
  uint64_t start;
  uint64_t end;
  uint64_t permissions;
};

uint64_t get_symbol_address(const char *name) {
  std::unordered_map<std::string, uint64_t>::iterator iter = symbol_table.find(name);
  if(iter == symbol_table.end()) {
    printf("Error finding symbol %s\n", name);
    exit(0);
  }
  return iter->second;
}

uint64_t round_to_page_lower(uint64_t n) {
  uint64_t pagesize = getpagesize();
  return n - (n % pagesize);
}

uint64_t round_to_page_upper(uint64_t n) {
  uint64_t pagesize = getpagesize();
  uint64_t m = n % pagesize;
  if(m == 0) return n;
  return n + (pagesize - m);
}

uint64_t slide = 0;

vm_prot_t mach_protection_flags(uint64_t segment_protection) {
  vm_prot_t ret = 0;
  if(segment_protection & SEGMENT_READ)
    ret |= VM_PROT_READ;
  if(segment_protection & SEGMENT_WRITE)
    ret |= VM_PROT_WRITE;
  if(segment_protection & SEGMENT_EXEC)
    ret |= VM_PROT_EXECUTE;
  
  return ret;
}

void *load(char *filename, bool rebased, std::unordered_map<uint64_t, uint64_t> &address_replacements, std::unordered_map<std::string, uint64_t> &symbol_replacements) {
  FILE *fp = fopen(filename, "rb");
  if(!fp) {
    printf("Error opening %s\n", filename);
    return NULL;
  }
  
  uint64_t numsegments = 0;
  fread(&numsegments, sizeof(uint64_t), 1, fp);
  Segment *segments = new Segment[numsegments];
  
  if(!numsegments) {
    printf("No segments\n");
    return NULL;
  }
  
  for(uint64_t i=0; i<numsegments; i++) {
    fread(&segments[i].start, sizeof(uint64_t), 1, fp);
    fread(&segments[i].end, sizeof(uint64_t), 1, fp);
    fread(&segments[i].permissions, sizeof(uint64_t), 1, fp);
  }
  
  uint64_t page_start = round_to_page_lower(segments[0].start);
  uint64_t page_end = round_to_page_upper(segments[numsegments-1].end);
  
  // printf("start: 0x%llx, end: 0x%llx\n", page_start, page_end);
  
  uint64_t allocation_size = page_end - page_start;
  
  kern_return_t krt;
  
  uint8_t *alloc_address = NULL;
  if(rebased) {
    alloc_address = (uint8_t *)page_start;
    krt = mach_vm_allocate(mach_task_self(),
                           (mach_vm_address_t*)&alloc_address,
                           allocation_size,
                           VM_FLAGS_FIXED);
  } else {
    krt = mach_vm_allocate(mach_task_self(),
                           (mach_vm_address_t*)&alloc_address,
                           allocation_size,
                           VM_FLAGS_ANYWHERE);
  }


  if (krt != KERN_SUCCESS) {
    printf("Error allocating memory. Did you forget to rebase?\n");
    fclose(fp);
    return NULL;
  }
  
  // printf("Allocated at: %p\n", alloc_address);

  slide = page_start - (uint64_t)alloc_address;

  // printf("Slide: 0x%llx\n", slide);
  
  // fill with breakpoint instructions 
  // so we catch any attempt to execute outside what was loaded
  uint32_t *alloc_ints = (uint32_t *)alloc_address;
  for(uint64_t i = 0; i < (allocation_size / 4); i++) {
    alloc_ints[i] = BREAKPOINT;
  }
  
  for(uint64_t i=0; i<numsegments; i++) {
    uint64_t seg_size = segments[i].end - segments[i].start;
    fread((void *)(segments[i].start - slide), 1, seg_size, fp);
  }

  // load symbols
  uint64_t nsymbols;
  uint64_t symbols_size;
  fread(&nsymbols, sizeof(uint64_t), 1, fp);
  fread(&symbols_size, sizeof(uint64_t), 1, fp);
  
  char *buf = (char *)malloc(symbols_size + 2 * sizeof(uint64_t));
  ((uint64_t *)buf)[0] = nsymbols;
  ((uint64_t *)buf)[1] = symbols_size;
  fread(buf + 2 * sizeof(uint64_t), symbols_size, 1, fp);
  
  char *p = buf + 2 * sizeof(uint64_t);
  for(uint64_t i = 0; i < nsymbols; i++) {
    uint64_t addr = *(uint64_t *)p;
    p += sizeof(uint64_t);
    char *name = p;
    p += strlen(name) + 1;
    symbol_table[name] = addr;
  }

  for(std::unordered_map<uint64_t, uint64_t>::iterator iter = address_replacements.begin(); iter != address_replacements.end(); iter++) {
    uint64_t original_address = iter->first;
    uint64_t replacement_address = iter->second;
    if((original_address >= page_start) && (original_address < page_end)) {
      *(uint32_t *)original_address = BREAKPOINT;
    }
    tinyinst_register_replacement(original_address, replacement_address);
  }
  
  for(std::unordered_map<std::string, uint64_t>::iterator iter = symbol_replacements.begin(); iter != symbol_replacements.end(); iter++) {
    uint64_t original_address = get_symbol_address(iter->first.c_str());
    uint64_t replacement_address = iter->second;
    if((original_address >= page_start) && (original_address < page_end)) {
      *(uint32_t *)original_address = BREAKPOINT;
    }
    tinyinst_register_replacement(original_address, replacement_address);
  }
  
  for(uint64_t i=0; i<numsegments; i++) {
    uint64_t prot = segments[i].permissions;
    uint64_t prot_start = round_to_page_lower(segments[i].start);
    uint64_t prot_end = round_to_page_upper(segments[i].end);
    while(((i+1) < numsegments - 1) && (prot == segments[i+1].permissions)) {
      i++;
      prot_end = round_to_page_upper(segments[i+1].end);
    }
    
    krt = mach_vm_protect(mach_task_self(), prot_start - slide, prot_end - prot_start, false, mach_protection_flags(prot));
    if (krt != KERN_SUCCESS) {
      printf("Error (%s) applying memory protection @ 0x%llx\n", mach_error_string(krt), prot_start);
      fclose(fp);
      return NULL;
    }
  }
  
  fclose(fp);
  
  tinyinst_instrument_range(page_start, page_end);

  return (void *)page_start;
}

