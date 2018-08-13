//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENHANDLE_HPP
#define XENDBG_XENHANDLE_HPP

#include <memory>

#include <xenctrl.h>
#include <xenstore.h>
#include <xenforeignmemory.h>

namespace xd::xen {

  class XenHandle {
  public:
    XenHandle();

  private:
    class Version {
    public:
      explicit Version(int version);
      int major() { return _major; };
      int minor() { return _minor; };
    private:
      const int _major;
      const int _minor;
    };

  public:
    Version version() { return _version; }

  private:
    std::unique_ptr<xc_interface> _xenctrl;
    std::unique_ptr<struct xs_handle> _xenstore;
    std::unique_ptr<xenforeignmemory_handle> _foreign_memory;
    Version _version;
  };

}

#endif //XENDBG_XENHANDLE_HPP
