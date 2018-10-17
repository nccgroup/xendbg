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

DomInfo xd::xen::get_domain_info(XenCtrl &xenctrl, DomID domid) {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(xenctrl.get(), domid, 1, &dominfo);

  if (ret != 1 || dominfo.domid != domid)
    throw XenException("Failed to get domain info!", errno);

  return dominfo;
}

void Domain::set_debugging(bool enable, VCPU_ID vcpu_id) const {
  if (vcpu_id > get_info().max_vcpu_id)
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

std::optional<xd::xen::PageTableEntry> Domain::get_page_table_entry(Address address) const {
  // FYI: "cr3" is the register that holds the base address of the page table
  const auto cr3 = std::visit(util::overloaded {
    [](const auto &regs) {
      return regs.template get<reg::x86::cr3>();
    }}, get_cpu_context(0)); // TODO: is cr3 the same for every VCPU? I think it should be

  std::cout << "vaddr: " << address << std::endl;
  std::cout << "max gpfn: " << get_max_gpfn() << std::endl;
  std::cout << "CR3:   " << std::hex << cr3 << std::endl;

  std::cout << "L4 base MFN: " << (cr3 >> XC_PAGE_SHIFT) << std::endl;

  const auto l4 = PageTableEntry::read_level(*this, address, cr3 >> XC_PAGE_SHIFT,
      PageTableEntry::Level::L4);

  if (!(l4.is_present()))
    return std::nullopt;

  std::cout << "L3 base MFN: " << l4.get_mfn() << std::endl;

  const auto l3 = PageTableEntry::read_level(*this, address, l4.get_mfn(),
      PageTableEntry::Level::L3);

  if (!(l3.is_present()))
    return std::nullopt;

  std::cout << "L2 base MFN: " << l3.get_mfn() << std::endl;

  const auto l2 = PageTableEntry::read_level(*this, address, l3.get_mfn(),
      PageTableEntry::Level::L2);

  if (!(l2.is_present()))
    return std::nullopt;

  std::cout << "L1 base MFN: " << l2.get_mfn() << std::endl;

  const auto l1 = PageTableEntry::read_level(*this, address, l2.get_mfn(),
      PageTableEntry::Level::L1);

  std::cout << "MFN for vaddr: " << l1.get_mfn() << std::endl;

  return l1;
}

void Domain::pause_unpause_vcpu(uint32_t hypercall, VCPU_ID vcpu_id) const {
  hypercall_domctl(hypercall,
    [vcpu_id](auto &u) {
      auto &op = u.gdbsx_pauseunp_vcpu;
      op.vcpu = vcpu_id;
    });
}

void Domain::pause_unpause_vcpus_except(uint32_t hypercall, VCPU_ID vcpu_id) const {
  auto max_vcpu_id = get_info().max_vcpu_id;

  for (VCPU_ID id = 0; id <= max_vcpu_id; ++id) {
    if (id == vcpu_id)
      continue;
    pause_unpause_vcpu(hypercall, id);
  }
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
