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

// See xen/include/asm-x86/x86_64/page.h
#define PAGETABLE_ORDER 9
#define PAGETABLE_ENTRIES (1<<PAGETABLE_ORDER)

#define L1_PAGETABLE_SHIFT 12
#define L2_PAGETABLE_SHIFT 21
#define L3_PAGETABLE_SHIFT 30
#define L4_PAGETABLE_SHIFT 39

#define PADDR_BITS (64 - XC_PAGE_SHIFT)
#define PADDR_MASK ((1ULL << PADDR_BITS)-1)

#define GET_PTE_ADDRESS(pte) \
  (unsigned long)((pte & (PADDR_MASK & XC_PAGE_MASK)))

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

#define READ_PAGETABLE_LEVEL(level, virtual_address, pte_address, next_pte_address, flags) \
{ \
  std::cout << "table @ " << pte_address << std::endl; \
  const auto table = map_memory<PTE>(pte_address, XC_PAGE_SIZE, PROT_READ); \
  const auto pte = (table.get())[PTE_OFFSET(level, virtual_address)]; \
  std::cout << "pte = " << std::bitset<64>(pte) << std::endl; \
  flags = GET_PTE_FLAGS(pte); \
  next_pte_address = GET_PTE_ADDRESS(pte); \
}

uint64_t Domain::get_page_table_entry(Address address) const {
  using PTE = uint64_t;


  uint64_t flags, pte_address;
  // FYI: "cr3" is the register that holds the base address of the page table
  auto base = std::visit(util::overloaded {
    [](const auto &regs) {
      return regs.get<reg::x86::cr3>();
    }, get_cpu_context() });

  READ_PAGETABLE_LEVEL(4, address, base, pte_address, flags);

  std::cout << "L4: " << std::bitset<64>(flags) << std::endl;
  if (!(flags & _PAGE_PRESENT))
    return ~0;

  READ_PAGETABLE_LEVEL(3, address, pte_address, pte_address, flags);

  std::cout << "L3: " << std::bitset<64>(flags) << std::endl;
  if (!(flags & _PAGE_PRESENT) || (flags & _PAGE_PSE))
    return ~0;

  READ_PAGETABLE_LEVEL(2, address, pte_address, pte_address, flags);

  std::cout << "L2: " << std::bitset<64>(flags) << std::endl;
  if (!(flags & _PAGE_PRESENT) || (flags & _PAGE_PSE))
    return ~0;

  std::cout << "L1: " << std::bitset<64>(flags) << std::endl;
  READ_PAGETABLE_LEVEL(1, address, pte_address, pte_address, flags);

  return flags;
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
