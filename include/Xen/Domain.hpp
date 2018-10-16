//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include <Registers/RegistersX86Any.hpp>

#include "Common.hpp"
#include "PagePermissions.hpp"
#include "PageTableEntry.hpp"
#include "PrivCmd.hpp"
#include "XenEventChannel.hpp"
#include "XenCtrl.hpp"
#include "XenForeignMemory.hpp"
#include "XenStore.hpp"

namespace xd::xen {

  DomInfo get_domain_info(XenCtrl &xenctrl, DomID domid);

  class Domain {
  public:
    Domain(DomID domid, PrivCmd &privcmd, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
        XenForeignMemory &xenforeignmemory, XenStore &xenstore);
    virtual ~Domain() = default;

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

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0) const;

    Address translate_foreign_address(Address vaddr, VCPU_ID vcpu_id = 0) const;
    MemInfo map_meminfo() const;
    std::optional<PageTableEntry> get_page_table_entry(Address address) const;
    virtual std::optional<PagePermissions> get_page_permissions(Address address) const = 0;

    virtual xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const = 0;
    virtual void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const = 0;

    xen_domctl_gdbsx_domstatus get_domstatus() const {
      auto u = hypercall_domctl(XEN_DOMCTL_gdbsx_domstatus);
      return u.gdbsx_domstatus;
    };

    void pause_vcpu(VCPU_ID vcpu_id) const {
      pause_unpause_vcpu(XEN_DOMCTL_gdbsx_pausevcpu, vcpu_id);
    };

    void unpause_vcpu(VCPU_ID vcpu_id) const {
      pause_unpause_vcpu(XEN_DOMCTL_gdbsx_unpausevcpu, vcpu_id);
    };

    void pause_vcpus_except(VCPU_ID vcpu_id) const {
      pause_unpause_vcpus_except(XEN_DOMCTL_gdbsx_pausevcpu, vcpu_id);
    };

    void unpause_vcpus_except(VCPU_ID vcpu_id) const {
      pause_unpause_vcpus_except(XEN_DOMCTL_gdbsx_unpausevcpu, vcpu_id);
    };

    void pause() const;
    void unpause() const;
    void shutdown(int reason) const;
    void destroy() const;

    xen_pfn_t get_max_gpfn() const;

    PrivCmd::DomctlUnion hypercall_domctl(uint32_t command, PrivCmd::InitFn init = {}, PrivCmd::CleanupFn cleanup = {}) const {
      return _privcmd.hypercall_domctl(*this, command, std::move(init), std::move(cleanup));
    }

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory(Address address, size_t size, int prot) const {
      return _xenforeignmemory.map<Memory_t>(*this, address, size, prot);
    };

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory_by_mfn(Address mfn, Address offset, size_t size, int prot) const {
      return _xenforeignmemory.map_by_mfn<Memory_t>(*this, mfn, offset, size, prot);
    };

    void set_access_required(bool required);

    /*
    void reboot() const;
    void read_memory(Address address, void *data, size_t size) const;
    void write_memory(Address address, void *data, size_t size) const;
     */

  protected:
    DomID _domid;
    PrivCmd &_privcmd;
    XenEventChannel &_xenevtchn;
    XenCtrl &_xenctrl;
    XenForeignMemory &_xenforeignmemory;
    XenStore &_xenstore;

  private:
    void pause_unpause_vcpu(uint32_t hypercall, VCPU_ID vcpu_id) const;
    void pause_unpause_vcpus_except(uint32_t hypercall, VCPU_ID vcpu_id) const;
  };

}

#endif //XENDBG_DOMAIN_HPP
