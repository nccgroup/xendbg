//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include "Common.hpp"
#include "XenHandle.hpp"
#include "../Registers/RegistersX86.hpp"
#include "MemoryPermissions.hpp"

namespace xd::xen {

  class Domain {
  public:
    Domain(const XenHandle& xen, DomID domid);

    DomID get_domid() const { return _domid; };
    std::string get_name() const;
    std::string get_kernel_path() const;
    DomInfo get_info() const;
    int get_word_size() const;

    //void reboot() const;

    template<typename InitFn_t, typename CleanupFn_t>
    void hypercall_domctl(uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) const {
      _xen.get_privcmd().hypercall_domctl(*this, command, init_domctl, cleanup);
    }

    /*
    void read_memory(Address address, void *data, size_t size);
    void write_memory(Address address, void *data, size_t size);
    */

    MemInfo map_meminfo() const;
    MappedMemory map_memory(Address address, size_t size, int prot) const;
    MemoryPermissions get_memory_permissions(Address address) const;

    xd::reg::RegistersX86 get_cpu_context(VCPU_ID vcpu_id = 0) const;
    void set_cpu_context(xd::reg::RegistersX86 regs, VCPU_ID vcpu_id = 0) const;

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0) const;
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0) const;

    void pause() const;
    void unpause() const;
    void shutdown(int reason) const;
    void destroy() const;

  private:
    const XenHandle& _xen;
    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

