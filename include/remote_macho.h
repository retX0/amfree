#pragma once

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/types.h>

/*
 * Find the PID of the running amfid process.
 * Returns -1 if not found.
 */
pid_t find_amfid_pid(void);

/*
 * Resolve the IMP of -[AMFIPathValidator_macos validateWithError:].
 *
 * AMFIPathValidator_macos lives in AppleMobileFileIntegrity.framework, which
 * is part of the dyld shared cache.  The shared cache is mapped at the same
 * virtual address in every process for the lifetime of a boot session, so the
 * IMP address we resolve locally is identical to the address amfid sees.
 *
 * `task` is accepted for API symmetry but is not used for the IMP lookup.
 * If `dylib_base_out` is non-NULL it receives the framework's load address
 * (via dladdr) for informational purposes.
 *
 * Returns the IMP address, or 0 on failure.
 */
mach_vm_address_t find_method_imp(mach_port_t task,
                                  mach_vm_address_t *dylib_base_out);
