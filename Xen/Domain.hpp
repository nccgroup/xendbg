//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include "Common.hpp"

namespace xd::xen {

  class Xenctrl;
  class XenForeignMemory;
  class Xenstore;

  class Domain {
  public:
    Domain(Xenctrl& xenctrl, Xenstore& xenstore, XenForeignMemory& xen_foreign_memory, DomID domid);

    DomID domid() { return _domid; };
    std::string name();
    DomInfo info();
    int word_size();

    MappedMemory map_memory(Address address, size_t size, int prot);
    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0);
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0);
    void pause();
    void unpause();

  private:
    Xenctrl& _xenctrl;
    Xenstore& _xenstore;
    XenForeignMemory& _xen_foreign_memory;

    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

