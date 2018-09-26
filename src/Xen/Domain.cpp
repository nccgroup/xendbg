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
using xd::xen::XenHandlePtr;

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

xd::xen::PageTableEntry Domain::get_page_table_entry(Address address) const {
  // FYI: "cr3" is the register that holds the base address of the page table
  const auto cr3 = std::visit(util::overloaded {
    [](const auto &regs) {
      return regs.template get<reg::x86::cr3>();
    }}, get_cpu_context());

  const auto l4 = PageTableEntry::read_level(*this, address, cr3 >> XC_PAGE_SHIFT,
      PageTableEntry::Level::L4);

  if (!(l4.is_present()))
    throw std::runtime_error("L4: No such page!");

  const auto l3 = PageTableEntry::read_level(*this, address, l4.get_mfn(),
      PageTableEntry::Level::L3);

  if (!(l3.is_present()))
    throw std::runtime_error("L3: No such page!");

  const auto l2 = PageTableEntry::read_level(*this, address, l3.get_mfn(),
      PageTableEntry::Level::L2);

  if (!(l2.is_present()))
    throw std::runtime_error("L2: No such page!");

  return PageTableEntry::read_level(*this, address, l2.get_mfn(),
      PageTableEntry::Level::L1);
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

XenEventChannel::RingPageAndPort Domain::enable_monitor() const {
  return _xen->get_xenctrl().enable_monitor_for_domain(*this);
}

void Domain::disable_monitor() const {
  _xen->get_xenctrl().disable_monitor_for_domain(*this);
}

void Domain::monitor_software_breakpoint(bool enable) {
  _xen->get_xenctrl().monitor_software_breakpoint_for_domain(*this, enable);
}

void Domain::monitor_debug_exceptions(bool enable, bool sync) {
  _xen->get_xenctrl().monitor_debug_exceptions_for_domain(*this, enable, sync);
}

void Domain::monitor_cpuid(bool enable) {
  _xen->get_xenctrl().monitor_cpuid_for_domain(*this, enable);
}

void Domain::monitor_descriptor_access(bool enable) {
  _xen->get_xenctrl().monitor_descriptor_access_for_domain(*this, enable);
}

void Domain::monitor_privileged_call(bool enable) {
  _xen->get_xenctrl().monitor_privileged_call_for_domain(*this, enable);
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
