//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include "Common.hpp"
#include "Registers.hpp"
#include "XenHandle.hpp"

namespace xd::xen {

  class Domain {
  public:
    Domain(std::shared_ptr<XenHandle> xen, DomID domid);

    DomID get_domid() { return _domid; };
    std::string get_name();
    DomInfo get_info();
    int get_word_size();

    template<typename InitFn_t, typename CleanupFn_t>
    void hypercall_domctl(uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) {
      _xen->get_privcmd().hypercall_domctl(*this, command, init_domctl, cleanup);
    }

    MemInfo map_meminfo();
    MappedMemory map_memory(Address address, size_t size, int prot);
    Registers get_cpu_context(VCPU_ID vcpu_id = 0);
    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0);
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0);
    void pause();
    void unpause();

  private:
    std::shared_ptr<XenHandle> _xen;
    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

