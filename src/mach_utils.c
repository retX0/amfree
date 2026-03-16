#include "mach_utils.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>

kern_return_t remote_read(mach_port_t task, mach_vm_address_t addr,
                          void *buf, mach_vm_size_t size) {
    mach_vm_size_t out_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, size,
                                               (mach_vm_address_t)buf,
                                               &out_size);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "remote_read(0x%llx, %llu) failed: %s (%d)\n",
                addr, size, mach_error_string(kr), kr);
    }
    return kr;
}

kern_return_t remote_write(mach_port_t task, mach_vm_address_t addr,
                           const void *buf, mach_vm_size_t size) {
    kern_return_t kr = mach_vm_write(task, addr,
                                      (vm_offset_t)buf,
                                      (mach_msg_type_number_t)size);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "remote_write(0x%llx, %llu) failed: %s (%d)\n",
                addr, size, mach_error_string(kr), kr);
    }
    return kr;
}

mach_vm_address_t remote_alloc(mach_port_t task, mach_vm_size_t size,
                                vm_prot_t prot) {
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(task, &addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "remote_alloc(%llu) failed: %s (%d)\n",
                size, mach_error_string(kr), kr);
        return 0;
    }

    if (prot != (VM_PROT_READ | VM_PROT_WRITE)) {
        kr = mach_vm_protect(task, addr, size, FALSE, prot);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "remote_alloc: mach_vm_protect failed: %s (%d)\n",
                    mach_error_string(kr), kr);
            mach_vm_deallocate(task, addr, size);
            return 0;
        }
    }

    return addr;
}

kern_return_t remote_protect(mach_port_t task, mach_vm_address_t addr,
                              mach_vm_size_t size, vm_prot_t prot) {
    kern_return_t kr = mach_vm_protect(task, addr, size, FALSE, prot);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "remote_protect(0x%llx, %llu) failed: %s (%d)\n",
                addr, size, mach_error_string(kr), kr);
    }
    return kr;
}
