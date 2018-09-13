#include "XenMemoryPermissions.hpp"

using xd::xen::XenMemoryPermissions;

static inline bool has_read_permission(xenmem_access_t perm) {
  return perm == XENMEM_access_rw ||
         perm == XENMEM_access_rx ||
         perm == XENMEM_access_rwx ||
         perm == XENMEM_access_rx2rw;
}

static inline bool has_write_permission(xenmem_access_t perm) {
  return perm == XENMEM_access_rw ||
         perm == XENMEM_access_wx ||
         perm == XENMEM_access_rwx;
}

static inline bool has_execute_permission(xenmem_access_t perm) {
  return perm == XENMEM_access_x ||
         perm == XENMEM_access_rx ||
         perm == XENMEM_access_wx ||
         perm == XENMEM_access_rwx ||
         perm == XENMEM_access_rx2rw;
}

XenMemoryPermissions::XenMemoryPermissions(xenmem_access_t perm)
  : read(has_read_permission(perm)),
    write(has_write_permission(perm)),
    execute(has_execute_permission(perm)),
    rx_to_rw(perm == XENMEM_access_rx2rw),
    none_to_rwx(perm == XENMEM_access_n2rwx)
{
}
