//
// Created by Spencer Michaels on 8/13/18.
//

#include <Xen/Domain.hpp>
#include <Util/overloaded.hpp>
#include <Registers/RegistersX86.hpp>

using xd::reg::RegistersX86Any;
using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::MemInfo;
using xd::xen::XenCtrl;
using xd::xen::XenEventChannel;

DomInfo xd::xen::get_domain_info(XenCtrl &xenctrl, DomID domid) {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(xenctrl.get(), domid, 1, &dominfo);

  if (ret != 1 || dominfo.domid != domid)
    throw XenException("Failed to get domain info!", errno);

  return dominfo;
}

Domain::Domain(DomID domid, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
    XenForeignMemory &xenforeignmemory, XenStore &xenstore)
    : _domid(domid), _xenevtchn(xenevtchn), _xenctrl(xenctrl),
      _xenforeignmemory(xenforeignmemory), _xenstore(xenstore)
{
  get_info();
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

DomInfo Domain::get_info() const {
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

std::optional<xd::xen::PageTableEntry> Domain::get_page_table_entry(Address address) const {
  // FYI: "cr3" is the register that holds the base address of the page table
  const auto cr3 = std::visit(util::overloaded {
    [](const auto &regs) {
      return regs.template get<reg::x86::cr3>();
    }}, get_cpu_context());

  const auto l4 = PageTableEntry::read_level(*this, address, cr3 >> XC_PAGE_SHIFT,
      PageTableEntry::Level::L4);

  if (!(l4.is_present()))
    return std::nullopt;

  const auto l3 = PageTableEntry::read_level(*this, address, l4.get_mfn(),
      PageTableEntry::Level::L3);

  if (!(l3.is_present()))
    return std::nullopt;

  const auto l2 = PageTableEntry::read_level(*this, address, l3.get_mfn(),
      PageTableEntry::Level::L2);

  if (!(l2.is_present()))
    return std::nullopt;

  return PageTableEntry::read_level(*this, address, l2.get_mfn(),
      PageTableEntry::Level::L1);
}

void Domain::pause() const {
  const auto dominfo = get_info();
  if (dominfo.paused)
    return;

  int err;
  if ((err = xc_domain_pause(_xenctrl.get(), _domid)))
    throw XenException(
        "Failed to pause domain " + std::to_string(_domid), -err);
}

void Domain::unpause() const {
  const auto dominfo = get_info();
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

xen_pfn_t Domain::get_max_gpfn() const {
  xen_pfn_t max_gpfn;
  int err;
  if ((err = xc_domain_maximum_gpfn(_xenctrl.get(), _domid, &max_gpfn)))
    throw XenException(
        "Failed to destroy domain " + std::to_string(_domid), -err);
  return max_gpfn;
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
*/
