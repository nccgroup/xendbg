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

    PagePermissions(const PageTableEntry &pte)
      : read(true),
        write(pte.is_rw()),
        execute(!pte.is_nx())
    {}

    bool read, write, execute;
  };

}

#endif //XENDBG_PAGEPERMISSIONS_HPP
