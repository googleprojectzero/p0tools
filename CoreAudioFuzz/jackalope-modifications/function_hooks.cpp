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
