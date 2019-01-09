//
// Copyright (C) 2018-2019 Spencer Michaels
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainHVM.hpp>
#include <Xen/BridgeHeaders/hvm_save.h>
#include <Xen/BridgeHeaders/vm_event.h>
#include <Xen/Xen.hpp>

using xd::reg::RegistersX86Any;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::DomainHVM;
using xd::xen::PagePermissions;
using xd::xen::VCPU_ID;
using xd::xen::Xen;

#define GET_HVM(_regs, _hvm, _reg) \
  _regs.get<_reg>() = _hvm._reg;
#define GET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _regs.get<_reg>() = _hvm._hvm_reg;
#define SET_HVM(_regs, _hvm, _reg) \
  _hvm._reg = _regs.get<_reg>();
#define SET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _hvm._hvm_reg = _regs.get<_reg>();

DomainHVM::DomainHVM(DomID domid, std::shared_ptr<Xen> xen)
  : Domain(domid, std::move(xen))
{
}

RegistersX86Any DomainHVM::get_cpu_context(VCPU_ID vcpu_id) const {
  return convert_regs_from_hvm(get_cpu_context_raw(vcpu_id));
}

void DomainHVM::set_cpu_context(RegistersX86Any regs, VCPU_ID vcpu_id) const {
  const auto regs64 = std::get<RegistersX86_64>(regs);
  const auto old_context = get_cpu_context_raw(vcpu_id);
  const auto new_context = convert_regs_to_hvm(regs64, old_context);

  set_cpu_context_raw(new_context, vcpu_id);
}

void DomainHVM::set_singlestep(bool enable, VCPU_ID vcpu_id) const {
  uint32_t op = enable
                ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON
                : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (vcpu_id > get_dominfo().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
        " single-step mode for nonexistent VCPU " + std::to_string(vcpu_id) +
        " on domain " + std::to_string(_domid));

  int err;
  if ((err = xc_domain_debug_control(_xen->xenctrl.get(), _domid, op, vcpu_id))) {
    throw XenException(
        "Failed to " + std::string(enable ? "enable" : "disable") +
        " single-step mode for VCPU " + std::to_string(vcpu_id) + " on domain " +
        std::to_string(_domid), -err);
  }
}

xd::xen::XenEventChannel::RingPageAndPort DomainHVM::enable_monitor() const {
  uint32_t port;
  void *ring_page = xc_monitor_enable(_xen->xenctrl.get(), _domid, &port);

  if (!ring_page) {
    switch (errno) {
      case EBUSY:
        throw XenException("Monitoring is already active for this domain!");
      case ENODEV:
        throw XenException("This domain does not support EPT!");
      default:
        throw XenException("Failed to enable monitoring: "
                           + std::string(std::strerror(errno)));
    }
  }

  return {
      .ring_page = ring_page,
      .port = port
  };
}

void DomainHVM::disable_monitor() const {
  xc_monitor_disable(_xen->xenctrl.get(), _domid);
}

DomainHVM::MonitorCapabilities DomainHVM::monitor_get_capabilities() {
  uint32_t capabilities;
  xc_monitor_get_capabilities(_xen->xenctrl.get(), _domid, &capabilities);

  return MonitorCapabilities {
    .mov_to_msr = (bool) (capabilities & VM_EVENT_REASON_MOV_TO_MSR),
    .singlestep = (bool) (capabilities & VM_EVENT_REASON_SINGLESTEP),
    .software_breakpoint = (bool) (capabilities & VM_EVENT_REASON_SOFTWARE_BREAKPOINT),
    .descriptor_access = (bool) (capabilities & VM_EVENT_REASON_DESCRIPTOR_ACCESS),
    .guest_request = (bool) (capabilities & VM_EVENT_REASON_GUEST_REQUEST),
    .debug_exception = (bool) (capabilities & VM_EVENT_REASON_DEBUG_EXCEPTION),
    .cpuid_privileged_call = (bool) (capabilities & VM_EVENT_REASON_PRIVILEGED_CALL),
  };
}

void DomainHVM::monitor_mov_to_msr(uint32_t msr, bool enable) {
  xc_monitor_mov_to_msr(_xen->xenctrl.get(), _domid, msr, enable);
}

void DomainHVM::monitor_singlestep(bool enable) {
  xc_monitor_singlestep(_xen->xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_software_breakpoint(bool enable) {
  xc_monitor_software_breakpoint(_xen->xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_debug_exceptions(bool enable, bool sync) {
  xc_monitor_debug_exceptions(_xen->xenctrl.get(), _domid, enable, sync);
}

void DomainHVM::monitor_cpuid(bool enable) {
  xc_monitor_cpuid(_xen->xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_descriptor_access(bool enable) {
  xc_monitor_descriptor_access(_xen->xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_privileged_call(bool enable) {
  xc_monitor_privileged_call(_xen->xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_guest_request(bool enable, bool sync) {
  xc_monitor_guest_request(_xen->xenctrl.get(), _domid, enable, sync);
}

struct hvm_hw_cpu DomainHVM::get_cpu_context_raw(VCPU_ID vcpu_id) const {
  int err;
  struct hvm_hw_cpu context;
  if ((err = xc_domain_hvm_getcontext_partial(_xen->xenctrl.get(), _domid,
      HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &context, sizeof(context))))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }

  return context;
}

// from tools/libxc/xc_dom_x86.c
// TODO: does this even work??
void DomainHVM::set_cpu_context_raw(struct hvm_hw_cpu context, VCPU_ID vcpu_id) const {
  struct {
      struct hvm_save_descriptor header_d;
      HVM_SAVE_TYPE(HEADER) header;
      struct hvm_save_descriptor cpu_d;
      HVM_SAVE_TYPE(CPU) cpu;
      struct hvm_save_descriptor end_d;
      HVM_SAVE_TYPE(END) end;
  } context_update;

  uint32_t size = xc_domain_hvm_getcontext(_xen->xenctrl.get(), _domid, nullptr, 0);
  if (size == ((uint32_t)-1))
    throw std::runtime_error("Failed to get HVM domain context (1)!");

  std::unique_ptr<uint8_t> full_context((uint8_t*)calloc(1, size));

  size = xc_domain_hvm_getcontext(_xen->xenctrl.get(), _domid, full_context.get(), size);
  if (size == ((uint32_t)-1))
    throw std::runtime_error("Failed to get HVM domain context (2)!");

  memset(&context_update, 0, sizeof(context_update));
  memcpy(&context_update, full_context.get(),
      sizeof(struct hvm_save_descriptor) + HVM_SAVE_LENGTH(HEADER));

  /*
  context_update.header_d.typecode = HVM_SAVE_CODE(HEADER);
  context_update.header_d.instance = vcpu_id;
  context_update.header_d.length = HVM_SAVE_LENGTH(HEADER);
   */

  context_update.cpu_d.typecode = HVM_SAVE_CODE(CPU);
  context_update.cpu_d.instance = vcpu_id;
  context_update.cpu_d.length = HVM_SAVE_LENGTH(CPU);

  context_update.cpu = context;

  context_update.end_d.typecode = HVM_SAVE_CODE(END);
  context_update.end_d.instance = vcpu_id;
  context_update.end_d.length = HVM_SAVE_LENGTH(END);

  const int ret = xc_domain_hvm_setcontext(_xen->xenctrl.get(), _domid,
      (uint8_t*)&context_update, sizeof(context_update));
  if (ret)
    throw std::runtime_error("Failed to set HVM domain context!");
}

RegistersX86Any DomainHVM::convert_regs_from_hvm(const struct hvm_hw_cpu &hvm) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

  RegistersX86_64 regs;

  GET_HVM(regs, hvm, rax);
  GET_HVM(regs, hvm, rbx);
  GET_HVM(regs, hvm, rcx);
  GET_HVM(regs, hvm, rdx);
  GET_HVM(regs, hvm, rsp);
  GET_HVM(regs, hvm, rbp);
  GET_HVM(regs, hvm, rsi);
  GET_HVM(regs, hvm, rdi);
  GET_HVM(regs, hvm, r8);
  GET_HVM(regs, hvm, r9);
  GET_HVM(regs, hvm, r10);
  GET_HVM(regs, hvm, r11);
  GET_HVM(regs, hvm, r12);
  GET_HVM(regs, hvm, r13);
  GET_HVM(regs, hvm, r14);
  GET_HVM(regs, hvm, r15);
  GET_HVM(regs, hvm, rip);
  GET_HVM(regs, hvm, rflags);
  GET_HVM2(regs, hvm, fs, fs_base);
  GET_HVM2(regs, hvm, gs, gs_base);
  GET_HVM2(regs, hvm, cs, cs_base);
  GET_HVM2(regs, hvm, ds, ds_base);
  GET_HVM2(regs, hvm, ss, ss_base);
  GET_HVM(regs, hvm, cr0);
  GET_HVM(regs, hvm, cr3);
  GET_HVM(regs, hvm, cr4);
  GET_HVM(regs, hvm, msr_efer);

  return regs;
}

struct hvm_hw_cpu DomainHVM::convert_regs_to_hvm(const RegistersX86_64 &regs, hvm_hw_cpu hvm) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

  SET_HVM(regs, hvm, rax);
  SET_HVM(regs, hvm, rbx);
  SET_HVM(regs, hvm, rcx);
  SET_HVM(regs, hvm, rdx);
  SET_HVM(regs, hvm, rsp);
  SET_HVM(regs, hvm, rbp);
  SET_HVM(regs, hvm, rsi);
  SET_HVM(regs, hvm, rdi);
  SET_HVM(regs, hvm, r8);
  SET_HVM(regs, hvm, r9);
  SET_HVM(regs, hvm, r10);
  SET_HVM(regs, hvm, r11);
  SET_HVM(regs, hvm, r12);
  SET_HVM(regs, hvm, r13);
  SET_HVM(regs, hvm, r14);
  SET_HVM(regs, hvm, r15);
  SET_HVM(regs, hvm, rip);
  SET_HVM(regs, hvm, rflags);
  SET_HVM2(regs, hvm, fs, fs_base);
  SET_HVM2(regs, hvm, gs, gs_base);
  SET_HVM2(regs, hvm, cs, cs_base);
  SET_HVM2(regs, hvm, ds, ds_base);
  SET_HVM2(regs, hvm, ss, ss_base);
  SET_HVM(regs, hvm, cr0);
  SET_HVM(regs, hvm, cr3);
  SET_HVM(regs, hvm, cr4);
  SET_HVM(regs, hvm, msr_efer);

  return hvm;
}
