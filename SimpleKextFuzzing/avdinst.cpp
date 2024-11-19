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

#define _CRT_SECURE_NO_WARNINGS

#include "avdinst.h"

#include "common.h"

#define TINYINST_REGISTER_REPLACEMENT 0x747265706C616365
#define TINYINST_CUSTOM_INSTRUMENT 0x747265706C616366

void AVDInst::RegisterReplacementHook() {
  uint64_t original_address = GetRegister(X0);
  uint64_t replacement_address = GetRegister(X1);

  // printf("In RegisterReplacementHook %zx, %zx\n", original_address, replacement_address);

  redirects[original_address] = replacement_address;

  SetRegister(ARCH_PC, GetRegister(LR));
}


void AVDInst::InstrumentCustomRange() {
  uint64_t min_address = GetRegister(X0);
  uint64_t max_address = GetRegister(X1);

  printf("In InstrumentCustomRange %zx, %zx\n", min_address, max_address);
  
  InstrumentAddressRange("__custom_range__", min_address, max_address);

  SetRegister(ARCH_PC, GetRegister(LR));
}

void AVDInst::OnModuleInstrumented(ModuleInfo *module) {
  if(module->module_name == "__custom_range__") {
    instrumented_redirects.clear();
  }
  LiteCov::OnModuleInstrumented(module);
}

InstructionResult AVDInst::InstrumentInstruction(ModuleInfo *module,
                                        Instruction& inst,
                                        size_t bb_address,
                                        size_t instruction_address)
{
  auto iter = redirects.find(instruction_address);
  if(iter != redirects.end()) {
    instrumented_redirects[assembler_->Breakpoint(module)] = iter->second;
    return INST_STOPBB;
  }
  
  return LiteCov::InstrumentInstruction(module, inst, bb_address, instruction_address);
}

bool AVDInst::OnException(Exception *exception_record) {
  size_t exception_address;

  if(exception_record->type == BREAKPOINT)
  {
    exception_address = (size_t)exception_record->ip;
  } else if(exception_record->type == ACCESS_VIOLATION) {
    exception_address = (size_t)exception_record->access_address;
  } else {
    return LiteCov::OnException(exception_record);
  }

  if(exception_address == TINYINST_REGISTER_REPLACEMENT) {
    RegisterReplacementHook();
    return true;
  }

  if(exception_address == TINYINST_CUSTOM_INSTRUMENT) {
    InstrumentCustomRange();
    return true;
  }
  
  auto iter = redirects.find(exception_address);
  if(iter != redirects.end()) {
    // printf("Redirecting...\n");
    SetRegister(ARCH_PC, iter->second);
    return true;
  }

  iter = instrumented_redirects.find(exception_address);
  if(iter != instrumented_redirects.end()) {
    // printf("Redirecting...\n");
    SetRegister(ARCH_PC, iter->second);
    return true;
  }
    
  return LiteCov::OnException(exception_record);
}
