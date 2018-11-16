//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>
#include <vector>

#include <Registers/RegistersX86Any.hpp>

#include "Common.hpp"
#include "PagePermissions.hpp"
#include "PageTableEntry.hpp"
#include "XenCall.hpp"
#include "XenForeignMemory.hpp"

namespace xd::xen {

  class Xen;

  class Domain {
  public:
    Domain(DomID domid, std::shared_ptr<Xen> xen);
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
    DomInfo get_dominfo() const;
    int get_word_size() const;

    void set_debugging(bool enabled, VCPU_ID vcpu_id) const;
    virtual void set_singlestep(bool enabled, VCPU_ID vcpu_id) const = 0;

    Address translate_foreign_address(Address vaddr, VCPU_ID vcpu_id) const;
    MemInfo map_meminfo() const;
    std::optional<PageTableEntry> get_page_table_entry(Address address, VCPU_ID vcpu_id) const;

    void set_mem_access(xenmem_access_t access, Address start_address, Address size) const;
    xenmem_access_t get_mem_access(Address pfn) const;

    virtual xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id) const = 0;
    virtual void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id) const = 0;

    void pause_vcpu(VCPU_ID vcpu_id);
    void unpause_vcpu(VCPU_ID vcpu_id);
    void pause_vcpus_except(VCPU_ID vcpu_id);
    void unpause_vcpus_except(VCPU_ID vcpu_id);
    void pause_all_vcpus();
    void unpause_all_vcpus();

    void pause() const;
    void unpause() const;
    void shutdown(int reason) const;
    void destroy() const;

    xen_pfn_t get_max_gpfn() const;

    XenCall::DomctlUnion hypercall_domctl(uint32_t command, XenCall::InitFn init = {}, XenCall::CleanupFn cleanup = {}) const;

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory(Address address, size_t size, int prot) const {
      return get_xenforeignmemory().map_by_mfn<Memory_t>(
          *this, translate_foreign_address(address, 0), address % XC_PAGE_SIZE, size, prot);
    };

    template <typename Memory_t>
    XenForeignMemory::MappedMemory<Memory_t> map_memory_by_mfn(Address mfn, Address offset, size_t size, int prot) const {
      return get_xenforeignmemory().map_by_mfn<Memory_t>(*this, mfn, offset, size, prot);
    };

    void set_access_required(bool required);

    /*
    void reboot() const;
    void read_memory(Address address, void *data, size_t size) const;
    void write_memory(Address address, void *data, size_t size) const;
     */

  protected:
    DomID _domid;
    std::shared_ptr<Xen> _xen;
    std::vector<bool> _vcpu_pause_state;

  private:
    void pause_unpause_vcpu(uint32_t hypercall, VCPU_ID vcpu_id);
    void pause_unpause_vcpus_except(uint32_t hypercall, VCPU_ID vcpu_id);
    void pause_unpause_all_vcpus(uint32_t hypercall);

    XenForeignMemory &get_xenforeignmemory() const;
  };

}

#endif //XENDBG_DOMAIN_HPP
