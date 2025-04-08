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

#include "initialization.h"

int initMessageHandler(const char *libraryPath, const char *symbolName) {
    void *coreAudioBaseAddress = LoadLibrary(libraryPath);
    if (!coreAudioBaseAddress) {
        printf("Load libray failed\n");
        return 0;
    }
    void *symbol_address = GetSymbolAddress(coreAudioBaseAddress, symbolName);
    if(!symbol_address) {
        printf("Symbol lookup failed\n");
        return 0;
    }
    Mach_Processing_Function = (t_Mach_Processing_Function)symbol_address;
    
    return 1;
}

int initAudioHardwareServer(const char *libraryPath, const char *symbolName) {
    void *coreAudioBaseAddress = LoadLibrary(libraryPath);
    if (!coreAudioBaseAddress) {
        printf("LoadLibrary failed\n");
        return 0;
    }
    void *symbol_address = GetSymbolAddress(coreAudioBaseAddress, symbolName);
    if(!symbol_address) {
        printf("Symbol lookup failed\n");
        return 0;
    }
    AudioHardwareStartServer = (t_AudioHardwareStartServer)symbol_address;
    
    return 1;
}

int initNextObjectId(const char *libraryPath, const char *symbolName) {
    void *coreAudioBaseAddress = LoadLibrary(libraryPath);
    if (!coreAudioBaseAddress) {
        printf("LoadLibrary failed\n");
        return 0;
    }
    void *symbol_address = GetSymbolAddress(coreAudioBaseAddress, symbolName);
    if(!symbol_address) {
        printf("Symbol lookup failed\n");
        return 0;
    }
    NextObjectID = (uint64_t *)symbol_address;
    
    return 1;
}