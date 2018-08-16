//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include "Common.hpp"
#include "Registers.hpp"

namespace xd::xen {

  class XenCtrl;
  class XenForeignMemory;
  class XenStore;

  class Domain {
  public:
    Domain(XenCtrl& xenctrl, XenStore& xenstore, XenForeignMemory& xen_foreign_memory, DomID domid);

    DomID get_domid() { return _domid; };
    std::string get_name();
    DomInfo get_info();
    int get_word_size();

    MappedMemory map_memory(Address address, size_t size, int prot);
    Registers get_cpu_context(VCPU_ID vcpu_id = 0);
    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0);
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0);
    void pause();
    void unpause();

  private:
    XenCtrl& _xenctrl;
    XenStore& _xenstore;
    XenForeignMemory& _xen_foreign_memory;

    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

