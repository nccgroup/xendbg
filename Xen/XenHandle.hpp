//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_XENHANDLE_HPP
#define XENDBG_XENHANDLE_HPP

#include "PrivCmd.hpp"
#include "XenCtrl.hpp"
#include "XenForeignMemory.hpp"
#include "XenStore.hpp"

namespace xd::xen {

  /**
   * Handles to various resources used to control Xen dom0 and guests
   */
  class XenHandle {
  public:
    PrivCmd& get_privcmd() { return _privcmd; };
    XenCtrl& get_xenctrl() { return _xenctrl; };
    XenForeignMemory& get_xen_foreign_memory() { return _xen_foreign_memory; };
    XenStore& get_xenstore() { return _xenstore; };

  private:
    PrivCmd _privcmd;
    XenCtrl _xenctrl;
    XenForeignMemory _xen_foreign_memory;
    XenStore _xenstore;
  };

}

#endif //XENDBG_XENHANDLE_HPP
