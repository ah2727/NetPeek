#ifndef NPE_VM_COMPAT_H
#define NPE_VM_COMPAT_H

/*
 * VM API compatibility layer
 * Maps legacy npe_vm_* accessors to current API
 */

#include "npe_vm.h"

/* Legacy name used by old modules */
#ifndef npe_vm_get_lua
#define npe_vm_get_lua(vm) npe_vm_lua(vm)
#endif

#endif /* NPE_VM_COMPAT_H */