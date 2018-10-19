//
// Created by Spencer Michaels on 8/13/18.
//

#include <Xen/Domain.hpp>
#include <Util/overloaded.hpp>
#include <Registers/RegistersX86.hpp>

using xd::reg::RegistersX86Any;
using xd::xen::Address;
using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::MemInfo;
using xd::xen::XenCtrl;
using xd::xen::XenEventChannel;
using xd::xen::XenException;

#define CR0_PG 0x80000000
#define CR4_PAE 0x2
#define PTE_PSE 0x80
#define EFER_LMA 0x400

// from xc_private.c

static int xc_ffs8(uint8_t x) {
  int i;
  for ( i = 0; i < 8; i++ )
    if ( x & (1u << i) )
      return i+1;
  return 0;
}

static int xc_ffs16(uint16_t x) {
  uint8_t h = x>>8, l = x;
  return l ? xc_ffs8(l) : h ? xc_ffs8(h) + 8 : 0;
}

static int xc_ffs32(uint32_t x) {
  uint16_t h = x>>16, l = x;
  return l ? xc_ffs16(l) : h ? xc_ffs16(h) + 16 : 0;
}

static int xc_ffs64(uint64_t x) {
  uint32_t h = x>>32, l = x;
  return l ? xc_ffs32(l) : h ? xc_ffs32(h) + 32 : 0;
}

DomInfo xd::xen::get_domain_info(XenCtrl &xenctrl, DomID domid) {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(xenctrl.get(), domid, 1, &dominfo);

  if (ret != 1 || dominfo.domid != domid)
    throw XenException("Failed to get domain info!", errno);

  return dominfo;
}

void Domain::set_debugging(bool enable, VCPU_ID vcpu_id) const {
  if (vcpu_id > get_dominfo().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
        " debugging for nonexistent VCPU " + std::to_string(vcpu_id) +
        " on domain " + std::to_string(_domid));

  int err;
  if ((err = xc_domain_setdebugging(_xenctrl.get(), _domid, (unsigned int)enable))) {
    throw XenException(
        "Failed to enable debugging on domain " +
        std::to_string(_domid), -err);
  }
}

Domain::Domain(DomID domid, XenCall &privcmd, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
    XenForeignMemory &xenforeignmemory, XenStore &xenstore)
    : _domid(domid), _privcmd(privcmd), _xenevtchn(xenevtchn), _xenctrl(xenctrl),
      _xenforeignmemory(xenforeignmemory), _xenstore(xenstore)
{
  get_dominfo();
}

std::string Domain::get_name() const {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xenstore.read(path);
}

std::string Domain::get_kernel_path() const {
  const auto vm_path = "/local/domain/" + std::to_string(_domid) + "/vm";
  const auto vm = _xenstore.read(vm_path);
  const auto kernel_path = vm + "/image/kernel";
  return _xenstore.read(kernel_path);
}

DomInfo Domain::get_dominfo() const {
  return get_domain_info(_xenctrl, _domid);
}

int Domain::get_word_size() const {
  int err;
  unsigned int word_size;
  if ((err = xc_domain_get_guest_width(_xenctrl.get(), _domid, &word_size))) {
    throw XenException(
        "Failed to get word size for domain " + std::to_string(_domid),
        -err);
  }
  return word_size;
}

Address Domain::translate_foreign_address(Address vaddr, VCPU_ID vcpu_id) const {
  return xc_translate_foreign_address(_xenctrl.get(), _domid, vcpu_id, vaddr);
}

MemInfo Domain::map_meminfo() const {
  auto xenctrl_ptr = _xenctrl.get();
  auto deleter = [xenctrl_ptr](xc_domain_meminfo *p) {
    xc_unmap_domain_meminfo(xenctrl_ptr, p);
  };

  auto meminfo =
      std::unique_ptr<xc_domain_meminfo, decltype(deleter)>(
          new xc_domain_meminfo, deleter);
  std::memset(meminfo.get(), 0, sizeof(xc_domain_meminfo));

  int err;
  xc_domain_meminfo minfo;
  if ((err = xc_map_domain_meminfo(_xenctrl.get(), _domid, meminfo.get()))) {
    throw XenException(
        "Failed to map meminfo for domain " + std::to_string(_domid),
        -err);
  }

  return meminfo;
}

// modifierd version of xc_translate_foreign_address in xc_pagetab.c
std::optional<xd::xen::PageTableEntry> Domain::get_page_table_entry(Address vaddr, VCPU_ID vcpu_id) const {
  // FYI: "cr3" is the register that holds the base address of the page table
  const auto [cr0, cr3, cr4, msr_efer] = std::visit(util::overloaded {
    [](const auto &regs) {
      return std::make_tuple(
          regs.template get<reg::x86::cr0>(),
          regs.template get<reg::x86::cr3>(),
          regs.template get<reg::x86::cr4>(),
          regs.template get<reg::x86::msr_efer>());
    }}, get_cpu_context(vcpu_id));

    uint64_t paddr, mask, pte;
    size_t pt_levels;

    if (get_dominfo().hvm) {
      if (!(cr0 & CR0_PG))
        return vaddr >> XC_PAGE_SHIFT;
      pt_levels = (msr_efer & EFER_LMA) ? 4 : (cr4 & CR4_PAE) ? 3 : 2;
      paddr = cr3 & ((pt_levels == 3) ? ~0x1full : ~0xfffull);
    } else {
      if (get_word_size() == sizeof(uint64_t)) {
        pt_levels = 4;
        paddr = cr3;
      } else {
        pt_levels = 3;
        paddr = ((cr3 >> XC_PAGE_SHIFT) | (cr3 << 20)) << XC_PAGE_SHIFT;
      }
    }

  if (pt_levels == 4) {
    vaddr &= 0x0000ffffffffffffull;
    mask =  0x0000ff8000000000ull;
  } else if (pt_levels == 3) {
    vaddr &= 0x00000000ffffffffull;
    mask =  0x0000007fc0000000ull;
  } else {
    vaddr &= 0x00000000ffffffffull;
    mask =  0x00000000ffc00000ull;
  }
  size_t size = (pt_levels == 2 ? sizeof(uint32_t) : sizeof(uint64_t));

  /* Walk the pagetables */
  for (size_t level = pt_levels; level > 0; level--) {
    paddr += ((vaddr & mask) >> (xc_ffs64(mask) - 1)) * size;
    auto map = map_memory<char>(paddr, XC_PAGE_SIZE, PROT_READ);

    memcpy(&pte, map.get() + (paddr & (XC_PAGE_SIZE - 1)), size);

    if (!(pte & 1))
      return std::nullopt;

    paddr = pte & 0x000ffffffffff000ull;
    if ((level == 2 || (level == 3 && pt_levels == 4)) && (pte & PTE_PSE)) {
      mask = ((mask ^ ~-mask) >> 1); /* All bits below first set bit */
      return ((paddr & ~mask) | (vaddr & mask)) >> XC_PAGE_SHIFT;
    }
    mask >>= (pt_levels == 2 ? 10 : 9);
  }

  return pte;
}

void Domain::set_mem_access(xenmem_access_t access, Address start_pfn, uint32_t num_pages) const {
  if (const auto err = xc_set_mem_access(_xenctrl.get(), _domid, access, start_pfn, num_pages))
    throw XenException("xc_set_mem_access", -err);
}

xenmem_access_t Domain::get_mem_access(Address pfn) const {
  xenmem_access_t access;
  if (const auto err = xc_get_mem_access(_xenctrl.get(), _domid, pfn, &access))
    throw XenException("xc_get_mem_access", -err);
  return access;
}

void Domain::pause_unpause_vcpu(uint32_t hypercall, VCPU_ID vcpu_id) const {
  hypercall_domctl(hypercall,
    [vcpu_id](auto &u) {
      auto &op = u.gdbsx_pauseunp_vcpu;
      op.vcpu = vcpu_id;
    });
}

void Domain::pause_unpause_vcpus_except(uint32_t hypercall, VCPU_ID vcpu_id) const {
  auto max_vcpu_id = get_dominfo().max_vcpu_id;

  for (VCPU_ID id = 0; id <= max_vcpu_id; ++id) {
    if (id == vcpu_id)
      continue;
    pause_unpause_vcpu(hypercall, id);
  }
}

void Domain::pause() const {
  const auto dominfo = get_dominfo();
  if (dominfo.paused)
    return;

  int err;
  if ((err = xc_domain_pause(_xenctrl.get(), _domid)))
    throw XenException(
        "Failed to pause domain " + std::to_string(_domid), -err);
}

void Domain::unpause() const {
  const auto dominfo = get_dominfo();
  if (!dominfo.paused)
    return;

  int err;
  if ((err = xc_domain_unpause(_xenctrl.get(), _domid)))
    throw XenException(
        "Failed to unpause domain " + std::to_string(_domid), -err);
}

void Domain::shutdown(int reason) const {
  int err;
  if ((err = xc_domain_shutdown(_xenctrl.get(), _domid, reason)))
    throw XenException(
        "Failed to shutdown domain " + std::to_string(_domid), -err);
}

void Domain::destroy() const {
  // Need to send the domain a SHUTDOWN request first to free up resources
  shutdown(SHUTDOWN_poweroff);

  int err;
  if ((err = xc_domain_destroy(_xenctrl.get(), _domid)))
    throw XenException(
        "Failed to destroy domain " + std::to_string(_domid), -err);}

xen_pfn_t Domain::get_max_gpfn() const {
  xen_pfn_t max_gpfn;
  int err;
  if ((err = xc_domain_maximum_gpfn(_xenctrl.get(), _domid, &max_gpfn)))
    throw XenException(
        "Failed to destroy domain " + std::to_string(_domid), -err);
  return max_gpfn;
}

void Domain::set_access_required(bool required) {
  if (const auto err = xc_domain_set_access_required(_xenctrl.get(), _domid, required))
    throw XenException("xc_domain_set_access_required", -err);
}

// TODO: This doesn't seem to have any effect.
/*
void Domain::reboot() const {
  libxl_ctx *ctx;
  libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, nullptr);
  libxl_domain_reboot(ctx, _domid);
  libxl_ctx_free(ctx);
}

void Domain::read_memory(Address address, void *data, size_t size) const {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio,
    [address, data, size](auto u) {
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
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio,
    [address, data, size](auto u) {
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
*/
