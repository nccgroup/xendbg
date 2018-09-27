//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include <Registers/RegistersX86Any.hpp>

#include "Common.hpp"
#include "PageTableEntry.hpp"
#include "XenEventChannel.hpp"
#include "XenHandle.hpp"

namespace xd::xen {

  DomInfo get_domain_info(DomID domid) const {
    xc_dominfo_t dominfo;
    int ret = xc_domain_getinfo(_xenctrl.get(), _domid, 1, &dominfo);

    if (ret != 1 || dominfo.domid != _domid)
      throw XenException("Failed to get domain info!", errno);

    return dominfo;
  }

  class Domain {
  public:
    Domain(DomID domid, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
        XenForeignMemory &xenforiegnmemory, XenStore &xenstore);

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

    MemInfo map_meminfo() const;
    PageTableEntry get_page_table_entry(Address address) const;

    PageTableEntry get_page_table_entry(Address address);
    virtual xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const = 0;
    virtual void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const = 0;

    void pause() const;
    void unpause() const;
    void shutdown(int reason) const;
    void destroy() const;

    xen_pfn_t pfn_to_mfn_pv(xen_pfn_t pfn) const;

    template<typename InitFn_t, typename CleanupFn_t>
    void hypercall_domctl(uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) const {
      _xen->get_privcmd().hypercall_domctl(*this, command, init_domctl, cleanup);
    }

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory(Address address, size_t size, int prot) const {
      return _xen->get_xen_foreign_memory().map<Memory_t>(*this, address, size, prot);
    };

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory_by_mfn(Address mfn, Address offset, size_t size, int prot) const {
      return _xen->get_xen_foreign_memory().map_by_mfn<Memory_t>(*this, mfn, offset, size, prot);
    };

    /*
    void reboot() const;
    void read_memory(Address address, void *data, size_t size) const;
    void write_memory(Address address, void *data, size_t size) const;
    */

  protected:
    DomID _domid;
    XenEventChannel &_xenevtchn;
    XenCtrl &_xenctrl;
    XenForeignMemory &_xenforiegnmemory;
    XenStore &_xenstore;
  };

}

#endif //XENDBG_DOMAIN_HPP
