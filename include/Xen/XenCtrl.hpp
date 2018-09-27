//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/ioctl.h>

#include <Registers/RegistersX86Any.hpp>

#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"
#include "Common.hpp"
#include "XenEventChannel.hpp"

namespace xd::xen {

  class Domain;

  class XenCtrl {
  private:
    struct XenVersion {
      int major, minor;
    };

  public:
    XenCtrl();

    xc_interface *get() const { return _xenctrl.get(); };
    XenVersion get_xen_version() const;

  private:
    std::shared_ptr<xc_interface> _xenctrl;
  };

}

#endif //XENDBG_XENCTRL_HPP
