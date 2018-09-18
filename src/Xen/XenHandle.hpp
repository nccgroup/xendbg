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
    const PrivCmd& get_privcmd() const { return _privcmd; };
    const XenCtrl& get_xenctrl() const { return _xenctrl; };
    const XenForeignMemory& get_xen_foreign_memory() const { return _xen_foreign_memory; };
    const XenStore& get_xenstore() const { return _xenstore; };

  private:
    PrivCmd _privcmd;
    XenCtrl _xenctrl;
    XenForeignMemory _xen_foreign_memory;
    XenStore _xenstore;
  };

}

#endif //XENDBG_XENHANDLE_HPP
