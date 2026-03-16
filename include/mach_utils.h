#pragma once

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>

/*
 * Remote memory read: copies `size` bytes from `addr` in `task` into `buf`.
 * Returns KERN_SUCCESS on success.
 */
kern_return_t remote_read(mach_port_t task, mach_vm_address_t addr,
                          void *buf, mach_vm_size_t size);

/*
 * Remote memory write: writes `size` bytes from `buf` into `addr` in `task`.
 * Returns KERN_SUCCESS on success.
 */
kern_return_t remote_write(mach_port_t task, mach_vm_address_t addr,
                           const void *buf, mach_vm_size_t size);

/*
 * Allocate `size` bytes in `task` with the given vm_prot_t `prot`.
 * Returns the allocated address, or 0 on failure.
 */
mach_vm_address_t remote_alloc(mach_port_t task, mach_vm_size_t size,
                                vm_prot_t prot);

/*
 * Change memory protection of `size` bytes at `addr` in `task` to `prot`.
 * Returns KERN_SUCCESS on success.
 */
kern_return_t remote_protect(mach_port_t task, mach_vm_address_t addr,
                              mach_vm_size_t size, vm_prot_t prot);
