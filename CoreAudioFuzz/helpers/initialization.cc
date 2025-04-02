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