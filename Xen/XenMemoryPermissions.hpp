//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENMEMORYPERMISSIONS_HPP
#define XENDBG_XENMEMORYPERMISSIONS_HPP

#include "BridgeHeaders/xenctrl.h"

namespace xd::xen {

    struct XenMemoryPermissions {
      XenMemoryPermissions(xenmem_access_t perm);

      const uint8_t read:1, write:1, execute:1,
                    rx_to_rw:1, none_to_rwx:1;
    };

}

#endif //XENDBG_XENMEMORYPERMISSIONS_HPP
