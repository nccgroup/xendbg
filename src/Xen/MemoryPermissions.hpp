//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_MEMORYPERMISSIONS_HPP
#define XENDBG_MEMORYPERMISSIONS_HPP

#include "BridgeHeaders/xenctrl.h"

namespace xd::xen {

    struct MemoryPermissions {
      MemoryPermissions(xenmem_access_t perm);

      const uint8_t read:1, write:1, execute:1,
                    rx_to_rw:1, none_to_rwx:1;
    };

}

#endif //XENDBG_MEMORYPERMISSIONS_HPP
