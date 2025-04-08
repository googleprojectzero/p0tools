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

#include "function_hooks.h"

void HALSWriteSettingHook::OnFunctionEntered() {
    printf("HALS_SettingsManager::_WriteSetting Entered\n");

    if (!GetRegister(RDX)) {
        printf("NULL plist passed as argument, returning to prevent NULL CFRelease\n");
        printf("Current $RSP: %p\n", GetRegister(RSP));

        void *return_address;
        
        RemoteRead((void*)GetRegister(RSP), &return_address, sizeof(void *));
        printf("Current return address: %p\n", GetReturnAddress());
        printf("Current $RIP: %p\n", GetRegister(RIP));

        SetRegister(RAX, 0);
        SetRegister(RIP, GetReturnAddress());

        printf("$RIP register is now: %p\n", GetRegister(ARCH_PC));

        SetRegister(RSP, GetRegister(RSP) + 8); // Simulate a ret instruction

        printf("$RSP is now: %p\n", GetRegister(RSP));
    }
}

FunctionHookInst::FunctionHookInst() {
    printf("Registering function hooks!\n");
    RegisterHook(new HALSWriteSettingHook());
}
