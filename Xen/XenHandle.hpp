//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENHANDLE_HPP
#define XENDBG_XENHANDLE_HPP

#include <memory>
#include <string>
#include <vector>

#include "Domain.hpp"
#include "ForeignMemory.hpp"
#include "Xenctrl.hpp"
#include "Xenstore.hpp"

struct xs_handle;
struct xenforeignmemory_handle;

namespace xd::xen {

  class XenHandle {
  public:
    Xenctrl& xenctrl() { return _xenctrl; }
    Xenstore& xenstore() { return _xenstore; }
    ForeignMemory& foreign_memory() { return _foreign_memory; }

  private:
    Xenctrl _xenctrl;
    Xenstore _xenstore;
    ForeignMemory _foreign_memory;
  };

}

#endif //XENDBG_XENHANDLE_HPP

