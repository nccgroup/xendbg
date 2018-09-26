//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include "Common.hpp"
#include "XenHandle.hpp"
#include "../Registers/RegistersX86Any.hpp"
#include "MemoryPermissions.hpp"

namespace xd::xen {

  class Domain {
  public:
    Domain(XenHandlePtr xen, DomID domid);

    bool operator==(const Domain &other) const {
      return _domid == other._domid;
    }
    bool operator!=(const Domain &other) const {
      return !operator==(other);
    }

    DomID get_domid() const { return _domid; };
    std::string get_name() const;
    std::string get_kernel_path() const;
    DomInfo get_info() const;
    int get_word_size() const;

    template<typename InitFn_t, typename CleanupFn_t>
    void hypercall_domctl(uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) const {
      _xen->get_privcmd().hypercall_domctl(*this, command, init_domctl, cleanup);
    }

    MemInfo map_meminfo() const;
    MemoryPermissions get_memory_permissions(Address address) const;

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory(Address address, size_t size, int prot) const {
      return _xen->get_xen_foreign_memory().map<Memory_t>(*this, address, size, prot);
    };

    PageTableEntry get_page_table_entry(Address address) const; // TODO

    xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const;
    void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const;

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0) const;
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0) const;

    void pause() const;
    void unpause() const;
    void shutdown(int reason) const;
    void destroy() const;

    /*
    void reboot() const;
    void read_memory(Address address, void *data, size_t size) const;
    void write_memory(Address address, void *data, size_t size) const;
    */

    xen_pfn_t pfn_to_mfn_pv(xen_pfn_t pfn) const;

  private:
    XenHandlePtr _xen;
    DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

