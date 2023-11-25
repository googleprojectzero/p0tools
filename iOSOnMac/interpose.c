#include <stdio.h>
#include <unistd.h>

typedef void* xpc_object_t;

extern xpc_object_t xpc_dictionary_create(void*, void*, int);
extern void xpc_dictionary_set_value(xpc_object_t, const char*, xpc_object_t);
extern xpc_object_t xpc_bool_create(int);
extern xpc_object_t xpc_copy_entitlements_for_self();

// From https://opensource.apple.com/source/dyld/dyld-97.1/include/mach-o/dyld-interposing.h.auto.html
/*
 *  Example:
 *
 *  static
 *  int
 *  my_open(const char* path, int flags, mode_t mode)
 *  {
 *    int value;
 *    // do stuff before open (including changing the arguments)
 *    value = open(path, flags, mode);
 *    // do stuff after open (including changing the return value(s))
 *    return value;
 *  }
 *  DYLD_INTERPOSE(my_open, open)
 */

#define DYLD_INTERPOSE(_replacment,_replacee) \
   __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

xpc_object_t my_xpc_copy_entitlements_for_self() {
    puts("[*] Faking com.apple.private.security.no-sandbox entitlement in interposed xpc_copy_entitlements_for_self");
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_value(dict, "com.apple.private.security.no-sandbox", xpc_bool_create(1));
    return dict;
}

DYLD_INTERPOSE(my_xpc_copy_entitlements_for_self, xpc_copy_entitlements_for_self);
