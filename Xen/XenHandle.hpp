//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENHANDLE_HPP
#define XENDBG_XENHANDLE_HPP

#include <memory>
#include <string>

#include <xenctrl.h>
#include <xenstore.h>
#include <xenforeignmemory.h>

#include "Domain.hpp"

namespace xd::xen {

  class XenHandle {
  public:
    struct Version {
      int major, minor;
    };

  public:
    XenHandle();

    Version version();

    Domain::DomID get_domid_from_name(const std::string& name);

  private:
    std::unique_ptr<xc_interface> _xenctrl;
    std::unique_ptr<struct xs_handle> _xenstore;
    std::unique_ptr<xenforeignmemory_handle> _foreign_memory;
  };

}

#endif //XENDBG_XENHANDLE_HPP

