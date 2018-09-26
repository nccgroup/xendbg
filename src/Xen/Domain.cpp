//
// Created by Spencer Michaels on 8/13/18.
//

// See tools/libxc/xg_private.h
#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE       0x080
#define _PAGE_GLOBAL    0x100
#define _PAGE_GNTTAB    (1U<<22)
#define _PAGE_NX        (1U<<23)
#define _PAGE_GUEST_KERNEL (1U<<12)

// See xen/include/asm-x86/x86_64/page.h
#define PAGETABLE_ORDER 9
#define PAGETABLE_ENTRIES (1<<PAGETABLE_ORDER)

#define L1_PAGETABLE_SHIFT 12
#define L2_PAGETABLE_SHIFT 21
#define L3_PAGETABLE_SHIFT 30
#define L4_PAGETABLE_SHIFT 39

#define PADDR_BITS (64 - XC_PAGE_SHIFT)
#define PADDR_MASK ((1ULL << PADDR_BITS)-1)

#define GET_PTE_MFN(pte) \
  ((unsigned long)((pte & (PADDR_MASK & XC_PAGE_MASK))) >> XC_PAGE_SHIFT)

#define PTE_OFFSET_L1(addr) \
  (((addr) >> L1_PAGETABLE_SHIFT) & (PAGETABLE_ENTRIES - 1))
#define PTE_OFFSET_L2(addr) \
  (((addr) >> L2_PAGETABLE_SHIFT) & (PAGETABLE_ENTRIES - 1))
#define PTE_OFFSET_L3(addr) \
  (((addr) >> L3_PAGETABLE_SHIFT) & (PAGETABLE_ENTRIES - 1))
#define PTE_OFFSET_L4(addr) \
  (((addr) >> L4_PAGETABLE_SHIFT) & (PAGETABLE_ENTRIES - 1))
#define PTE_OFFSET(level, address) \
  PTE_OFFSET_L ## level(address)

#define GET_PTE_FLAGS(pte) (((int)((pte) >> 40) & ~0xFFF) | ((int)(pte) & 0xFFF))
#define PUT_PTE_FLAGS(pte) (((intpte_t)((pte) & ~0xFFF) << 40) | ((pte) & 0xFFF))

#include "BridgeHeaders/libxl.h"

#include "Domain.hpp"
#include "../Util/overloaded.hpp"
#include "../Registers/RegistersX86.hpp"

using xd::reg::RegistersX86Any;
using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::MemInfo;
using xd::xen::XenCtrl;
using xd::xen::XenHandlePtr;
using xd::xen::MemoryPermissions;

Domain::Domain(XenHandlePtr xen, DomID domid)
    : _xen(std::move(xen)), _domid(domid)
{
  get_info(); // Make sure the domain is behaving properly
}

std::string Domain::get_name() const {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xen->get_xenstore().read(path);
}

std::string Domain::get_kernel_path() const {
  const auto vm_path = "/local/domain/" + std::to_string(_domid) + "/vm";
  const auto vm = _xen->get_xenstore().read(vm_path);
  const auto kernel_path = vm + "/image/kernel";
  return _xen->get_xenstore().read(kernel_path);
}

DomInfo Domain::get_info() const {
  return _xen->get_xenctrl().get_domain_info(*this);
}

int Domain::get_word_size() const {
  return _xen->get_xenctrl().get_domain_word_size(*this);
}

MemInfo Domain::map_meminfo() const {
  return _xen->get_xenctrl().map_domain_meminfo(*this);
}

MemoryPermissions Domain::get_memory_permissions(Address address) const {
  return _xen->get_xenctrl().get_domain_memory_permissions(*this, address);
}

#define READ_PAGETABLE_LEVEL(level, virtual_address, mfn, next_mfn, flags) \
{ \
  const auto table = _xen->get_xen_foreign_memory().map_mfn<PTE>(\
      *this, (mfn), 0, XC_PAGE_SIZE, PROT_READ); \
  const auto offset = PTE_OFFSET(level, (virtual_address)); \
  const auto pte = (table.get())[offset]; \
  next_mfn = GET_PTE_MFN(pte); \
  flags = GET_PTE_FLAGS(pte); \
}

xd::xen::PageTableEntry Domain::get_page_table_entry(Address address) const {
  using PTE = uint64_t;
  uint64_t flags, mfn;

  // FYI: "cr3" is the register that holds the base address of the page table
  const auto cr3 = std::visit(util::overloaded {
    [](const auto &regs) {
      return regs.template get<reg::x86::cr3>();
    }}, get_cpu_context());

  READ_PAGETABLE_LEVEL(4, address, cr3 >> XC_PAGE_SHIFT, mfn, flags);

  if (!(flags & _PAGE_PRESENT))
    throw std::runtime_error("No such page!");

  READ_PAGETABLE_LEVEL(3, address, mfn, mfn, flags);

  if (!(flags & _PAGE_PRESENT) || (flags & _PAGE_PSE))
    throw std::runtime_error("No such page!");

  READ_PAGETABLE_LEVEL(2, address, mfn, mfn, flags);

  if (!(flags & _PAGE_PRESENT) || (flags & _PAGE_PSE))
    throw std::runtime_error("No such page!");

  READ_PAGETABLE_LEVEL(1, address, mfn, mfn, flags);

  PageTableEntry pte;

  pte.present = (flags & _PAGE_PRESENT);
  pte.rw = (flags & _PAGE_RW);
  pte.user = (flags & _PAGE_USER);
  pte.pwt = (flags & _PAGE_PWT);
  pte.pcd = (flags & _PAGE_PCD);
  pte.accessed = (flags & _PAGE_ACCESSED);
  pte.dirty = (flags & _PAGE_DIRTY);
  pte.pat = (flags & _PAGE_PAT);
  pte.pse = (flags & _PAGE_PSE);
  pte.global = (flags & _PAGE_GLOBAL);
  pte.nx = (flags & _PAGE_NX);
  pte.gnttab = (flags & _PAGE_GNTTAB);
  pte.guest_kernel = (flags & _PAGE_GUEST_KERNEL);

  return pte;
}

RegistersX86Any Domain::get_cpu_context(VCPU_ID vcpu_id) const {
  return _xen->get_xenctrl().get_domain_cpu_context(*this, vcpu_id);
}

void Domain::set_cpu_context(RegistersX86Any regs, VCPU_ID vcpu_id) const {
  _xen->get_xenctrl().set_domain_cpu_context(*this, regs, vcpu_id);
}

void Domain::set_debugging(bool enabled, VCPU_ID vcpu_id) const {
  _xen->get_xenctrl().set_domain_debugging(*this, enabled, vcpu_id);
}

void Domain::set_single_step(bool enabled, VCPU_ID vcpu_id) const {
  _xen->get_xenctrl().set_domain_single_step(*this, enabled, vcpu_id);
}

void Domain::pause() const {
  _xen->get_xenctrl().pause_domain(*this);
}

void Domain::unpause() const {
  _xen->get_xenctrl().unpause_domain(*this);
}

void Domain::shutdown(int reason) const {
  _xen->get_xenctrl().shutdown_domain(*this, reason);
}

void Domain::destroy() const {
  _xen->get_xenctrl().destroy_domain(*this);
}

// TODO: This doesn't seem to have any effect.
/*
void Domain::reboot() const {
  libxl_ctx *ctx;
  libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, nullptr);
  libxl_domain_reboot(ctx, _domid);
  libxl_ctx_free(ctx);
}
*/

/*
void Domain::read_memory(Address address, void *data, size_t size) const {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [address, data, size](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = address;
    memio.uva = (uint64_aligned_t)((unsigned long)data);
    memio.len = size;
    memio.gwr = 0;

    if (mlock(data, size))
      throw XenException("mlock failed!", errno);
  }, [data, size]() {
    munlock(data, size);
  });
}

void Domain::write_memory(Address address, void *data, size_t size) const {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [address, data, size](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = address;
    memio.uva = (uint64_aligned_t)((unsigned long)data);
    memio.len = size;
    memio.gwr = 1;

    if (mlock(data, size))
      throw XenException("mlock failed!", errno);
  }, [data, size]() {
    munlock(data, size);
  });
}

// See xen/tools/libxc/xc_offline_page.c:389
xen_pfn_t Domain::pfn_to_mfn_pv(xen_pfn_t pfn) const {
  const auto meminfo = map_meminfo();
  const auto word_size = get_word_size();

  if (pfn > meminfo->p2m_size)
    throw XenException("Invalid PFN!");

  if (word_size == sizeof(uint64_t)) {
    return ((uint64_t*)meminfo->p2m_table)[pfn];
  } else {
    uint32_t mfn = ((uint32_t*)meminfo->p2m_table)[pfn];
    return (mfn == ~0U) ? INVALID_MFN : mfn;
  }
}
*/
