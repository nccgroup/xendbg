//
// Created by Spencer Michaels on 8/17/18.
//

#ifndef XENDBG_XENCONTEXT_HPP
#define XENDBG_XENCONTEXT_HPP

namespace xd::xen {
  class XenContext {
  public:
    PrivCmd privcmd;
    XenCtrl xenctrl;
    XenForeignMemory xen_foreign_memory;
    XenStore xenstore;
  };
}

#endif //XENDBG_XENCONTEXT_HPP
