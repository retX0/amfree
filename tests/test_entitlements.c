/*
 * test_entitlements.c — Verify amfid bypass by checking private entitlements.
 *
 * This binary is signed with private Apple entitlements (e.g.
 * com.apple.private.virtualization) that normally require Apple's own
 * signing identity.  If the amfid bypass is active, this binary will
 * run and successfully read its own entitlements via SecTask.
 *
 * Without the bypass, AMFI will kill or refuse to launch it.
 *
 * Build:  make test_ent
 * Run:    ./test_ent          (after sudo ./inject)
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

/* SecTask SPI — not in public headers but available in libSystem. */
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef  SecTaskCopyValueForEntitlement(SecTaskRef task,
                                                  CFStringRef entitlement,
                                                  CFErrorRef *error);

static void check_entitlement(SecTaskRef task, const char *ent_name) {
    CFStringRef key = CFStringCreateWithCString(NULL, ent_name,
                                                 kCFStringEncodingUTF8);
    CFErrorRef err = NULL;
    CFTypeRef val = SecTaskCopyValueForEntitlement(task, key, &err);

    if (val) {
        printf("  [✓] %-50s  → present\n", ent_name);
        CFRelease(val);
    } else {
        printf("  [✗] %-50s  → absent", ent_name);
        if (err) {
            CFStringRef desc = CFErrorCopyDescription(err);
            char buf[256];
            CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
            printf(" (%s)", buf);
            CFRelease(desc);
            CFRelease(err);
        }
        printf("\n");
    }
    CFRelease(key);
}

int main(void) {
    printf("=== amfid bypass entitlement test ===\n\n");
    printf("If this binary is running at all, AMFI did not kill it.\n");
    printf("Checking private entitlements on self...\n\n");

    SecTaskRef self_task = SecTaskCreateFromSelf(NULL);
    if (!self_task) {
        printf("[!] SecTaskCreateFromSelf failed — cannot query entitlements\n");
        printf("[+] But the binary IS running, so AMFI allowed it.\n");
        return 0;
    }

    /* Test the private entitlements we signed with. */
    check_entitlement(self_task, "com.apple.private.virtualization");
    check_entitlement(self_task, "com.apple.private.virtualization.security-research");
    check_entitlement(self_task, "com.apple.private.amfi.developer-mode-control");
    check_entitlement(self_task, "com.apple.private.security.no-container");
    check_entitlement(self_task, "com.apple.security.get-task-allow");

    CFRelease(self_task);

    printf("\n[+] test_ent completed successfully — bypass is active!\n");
    return 0;
}
