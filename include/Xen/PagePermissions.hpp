//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_PAGEPERMISSIONS_HPP
#define XENDBG_PAGEPERMISSIONS_HPP

#include "BridgeHeaders/xenctrl.h"
#include "PageTableEntry.hpp"

namespace xd::xen {

  struct PagePermissions {
    PagePermissions(bool read, bool write, bool execute)
      : read(read), write(write), execute(execute)
    {};

    PagePermissions(xenmem_access_t access)
      : read(access == XENMEM_access_r ||
             access == XENMEM_access_rw ||
             access == XENMEM_access_rx ||
             access == XENMEM_access_rwx ||
             access == XENMEM_access_rx2rw),
        write(access == XENMEM_access_w ||
              access == XENMEM_access_rw ||
              access == XENMEM_access_wx ||
              access == XENMEM_access_rwx),
        execute(access == XENMEM_access_x ||
                access == XENMEM_access_rx ||
                access == XENMEM_access_wx ||
                access == XENMEM_access_rwx ||
                access == XENMEM_access_rx2rw)
    {
    }

    PagePermissions(const PageTableEntry &pte)
      : read(true),
        write(pte.is_rw()),
        execute(!pte.is_nx())
    {}

    bool read, write, execute;
  };

}

#endif //XENDBG_PAGEPERMISSIONS_HPP
