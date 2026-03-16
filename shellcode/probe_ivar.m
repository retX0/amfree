/*
 * probe_ivar.m — Extract _code ivar offset from AMFIPathValidator_macos.
 *
 * Compiled and run at build time by the Makefile.
 * Prints the offset as a decimal integer to stdout.
 */
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdio.h>
#import <stdlib.h>

int main(void) {
    dlopen("/System/Library/PrivateFrameworks/"
           "AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity",
           RTLD_LAZY | RTLD_GLOBAL);

    Class cls = objc_getClass("AMFIPathValidator_macos");
    if (!cls) {
        fprintf(stderr, "probe_ivar: class AMFIPathValidator_macos not found\n");
        return 1;
    }

    Ivar ivar = class_getInstanceVariable(cls, "_code");
    if (!ivar) {
        fprintf(stderr, "probe_ivar: ivar _code not found\n");
        return 1;
    }

    printf("%td\n", ivar_getOffset(ivar));
    return 0;
}
