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

#ifndef AVDINST_H
#define AVDINST_H

#include <unordered_map>
#include <set>

#include "coverage.h"
#include "tinyinst.h"
#include "instruction.h"

#include "litecov.h"

class AVDInst : public LiteCov {
protected:
  virtual bool OnException(Exception *exception_record) override;
  virtual void OnModuleInstrumented(ModuleInfo *module) override;

  virtual InstructionResult InstrumentInstruction(ModuleInfo *module,
                                                  Instruction &inst,
                                                  size_t bb_address,
                                                  size_t instruction_address) override;

private:
  void RegisterReplacementHook();
  void InstrumentCustomRange();
  
  std::unordered_map<size_t, size_t> redirects;
  std::unordered_map<size_t, size_t> instrumented_redirects;
};

#endif // AVDINST_H
