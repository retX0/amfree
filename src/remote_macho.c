#include "remote_macho.h"
#include "shellcode/data_layout.h"

#include <dlfcn.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libproc.h>

pid_t find_amfid_pid(void) {
    /* Enumerate all PIDs and match by process name "amfid". */
    int buf_count = proc_listallpids(NULL, 0);
    if (buf_count <= 0) {
        return -1;
    }

    pid_t *pids = calloc((size_t)buf_count, sizeof(pid_t));
    if (!pids) {
        return -1;
    }

    int count = proc_listallpids(pids, buf_count * (int)sizeof(pid_t));
    pid_t result = -1;

    for (int i = 0; i < count; i++) {
        char name[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_name(pids[i], name, sizeof(name)) > 0) {
            if (strcmp(name, "amfid") == 0) {
                result = pids[i];
                break;
            }
        }
    }

    free(pids);
    return result;
}

mach_vm_address_t find_method_imp(mach_port_t task,
                                  mach_vm_address_t *dylib_base_out) {
    /*
     * AppleMobileFileIntegrity.framework is in the dyld shared cache, which is
     * mapped at the same virtual address in all processes for a given boot.
     * Resolving the IMP locally gives us the exact address valid in amfid.
     */
    (void)task;

    /* The framework lives in the dyld shared cache but is not automatically
     * loaded into our address space.  Force-load it so objc_getClass works. */
    dlopen("/System/Library/PrivateFrameworks/"
           "AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity",
           RTLD_LAZY | RTLD_GLOBAL);

    Class cls = objc_getClass(AMFI_CLASS_NAME);
    if (!cls) {
        fprintf(stderr, "find_method_imp: class %s not found\n", AMFI_CLASS_NAME);
        return 0;
    }

    Method m = class_getInstanceMethod(cls, sel_registerName("validateWithError:"));
    if (!m) {
        fprintf(stderr, "find_method_imp: validateWithError: not found on %s\n",
                AMFI_CLASS_NAME);
        return 0;
    }

    /* Strip PAC signature — the hook code runs via plain BLR, not BLRAA,
       so the stored IMP must be a clean (unsigned) pointer. */
    IMP imp = ptrauth_strip(method_getImplementation(m), ptrauth_key_function_pointer);

    if (dylib_base_out) {
        Dl_info info;
        if (dladdr((void *)imp, &info)) {
            *dylib_base_out = (mach_vm_address_t)info.dli_fbase;
        } else {
            *dylib_base_out = 0;
        }
    }

    return (mach_vm_address_t)imp;
}
