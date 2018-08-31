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
    Domain(XenHandle& xen, DomID domid);

    DomID get_domid() const { return _domid; };
    std::string get_name() const;
    std::string get_kernel_path() const;
    DomInfo get_info() const;
    int get_word_size() const;

    template<typename InitFn_t, typename CleanupFn_t>
    void hypercall_domctl(uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) const {
      _xen.get_privcmd().hypercall_domctl(*this, command, init_domctl, cleanup);
    }


    MemInfo map_meminfo() const;
    MappedMemory map_memory(Address address, size_t size, int prot) const;

    uint64_t read_register(const std::string &name, VCPU_ID vcpu_id = 0);
    void write_register(const std::string &name, uint64_t value, VCPU_ID vcpu_id = 0);

    Registers get_cpu_context(VCPU_ID vcpu_id = 0) const;
    void set_cpu_context(Registers regs, VCPU_ID vcpu_id = 0) const;

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0) const;
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0) const;

    void pause() const;
    void unpause() const;

  private:
    XenHandle& _xen;
    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

