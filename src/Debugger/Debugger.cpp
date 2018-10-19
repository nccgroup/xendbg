#include <Debugger/Debugger.hpp>

using xd::xen::Address;
using xd::xen::Domain;
using xd::dbg::Debugger;

Debugger::Debugger(uvw::Loop &loop, std::shared_ptr<xen::Domain> domain)
    : _timer(loop.resource<uvw::TimerHandle>()), _domain(std::move(domain)), _vcpu_id(0), _is_attached(false),
      _last_stop_signal(SIGSTOP)
{
  const auto mode =
      (_domain->get_word_size() == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

  if (cs_open(CS_ARCH_X86, mode, &_capstone) != CS_ERR_OK)
    throw CapstoneException("Failed to open Capstone handle!");

  cs_option(_capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

Debugger::~Debugger() {
  cs_close(&_capstone);

  if (_is_attached)
    this->detach();
}

void Debugger::attach() {
  _is_attached = true;
  _domain->pause();
  _domain->set_debugging(true, _vcpu_id);
  _timer->data(shared_from_this());
}

void Debugger::detach() {
  _domain->pause();
  cleanup();
  _domain->set_debugging(true, _vcpu_id);
  _domain->unpause();
  _is_attached = false;
}

void Debugger::continue_() {
  /*
  // Single step first to get past the current BP, if any
  const auto prev_on_stop = _on_stop;
  _on_stop = [this, prev_on_stop](auto signal) {
    _on_stop = prev_on_stop;
    _timer->start(uvw::TimerHandle::Time(10), uvw::TimerHandle::Time(100));
    _domain->unpause();
  };

  single_step();
  */

  _domain->unpause();
}

void Debugger::single_step() {
  const auto vcpu = _vcpu_id;

  const auto context = _domain->get_cpu_context(vcpu);
  const auto instr_ptr = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(context);
  if (_breakpoints.count(instr_ptr)) {
    _last_single_step_breakpoint_addr = instr_ptr;
    remove_breakpoint(instr_ptr);
  }

  _domain->pause_vcpus_except(vcpu);
  _domain->set_singlestep(true, vcpu);
  _last_single_step_vcpu_id = vcpu;

  _is_single_stepping = true;
  //_timer->start(uvw::TimerHandle::Time(100), uvw::TimerHandle::Time(100));
  _domain->unpause();
}

void Debugger::on_stop(OnStopFn on_stop) {
  _on_stop = std::move(on_stop);

  /*
  _timer->on<uvw::TimerEvent>([](const auto &event, auto &handle) {
    auto self = handle.template data<Debugger>();
    auto status = self->_domain->hypercall_domctl(XEN_DOMCTL_gdbsx_domstatus).gdbsx_domstatus;
    if (status.paused) {
      handle.stop();
      auto &domain = self->_domain;
      auto vcpu = (status.vcpu_id == -1)
                  ? self->_last_single_step_vcpu_id
                  : status.vcpu_id;

      // If we're stopping after a single step and there was a BP at the
      // address we came from, put it back
      if (self->_last_single_step_breakpoint_addr) {
        self->insert_breakpoint(*self->_last_single_step_breakpoint_addr);
        self->_last_single_step_breakpoint_addr = std::nullopt;
      }

      if (!self->_is_single_stepping) {
        \*
         * Otherwise, we came from continuing into a breakpoint.
         * PV breaks are a bit weird; the guest pauses on the *next* instruction.
         * Since 0xCC BPs are 1 byte, we can just set RIP back by that amount to get
         * to the actual instruction that was broken on.
         *\
        auto context_any = domain->get_cpu_context(vcpu);
        std::visit(util::overloaded {
          [](reg::x86_64::RegistersX86_64 &context) {
            context.get<reg::x86_64::rip>() -= 1;
          },
          [](reg::x86_32::RegistersX86_32 &context) {
            context.get<reg::x86_32::eip>() -= 1;
          }}, context_any);
        domain->set_cpu_context(context_any, vcpu);
      } else {
        self->_is_single_stepping = false;
        domain->set_singlestep(false, vcpu);
        domain->unpause_vcpus_except(vcpu);
      }

      self->set_vcpu_id(vcpu);
      self->on_stop_internal(SIGTRAP);
    }
  });
*/
}

void Debugger::on_stop_internal(int signal) {
  _last_stop_signal = signal;
  if (_on_stop)
    _on_stop(signal);
}

void Debugger::cleanup() {
  for (const auto &bp : _breakpoints) {
    std::cout << bp.first << std::endl;
    remove_breakpoint(bp.first);
  }
}

void Debugger::insert_breakpoint(Address address) {
  spdlog::get(LOGNAME_CONSOLE)->debug("Inserting breakpoint at {0:x}", address);

  if (_breakpoints.count(address)) {
    spdlog::get(LOGNAME_ERROR)->info(
        "[!]: Tried to insert breakpoint where one already exists. "
        "This is generally harmless, but might indicate a failure in estimating the "
        "next instruction address.",
        address);
    return;
  }

  const auto mem_handle = _domain->map_memory<uint8_t>(
      address, sizeof(uint8_t), PROT_READ | PROT_WRITE);
  const auto mem = mem_handle.get();

  const auto orig_bytes = *mem;

  _breakpoints[address] = orig_bytes;
  *mem = 0xCC;
}

void Debugger::remove_breakpoint(Address address) {
  spdlog::get(LOGNAME_CONSOLE)->debug("Removing breakpoint at {0:x}", address);

  if (!_breakpoints.count(address)) {
    spdlog::get(LOGNAME_ERROR)->info(
        "[!]: Tried to remove infinite loop where one does not exist. "
        "This is generally harmless, but might indicate a failure in estimating the "
        "next instruction address.",
        address);
    return;
  }

  const auto mem_handle = _domain->map_memory<uint8_t>(
      address, sizeof(uint8_t), PROT_WRITE);
  const auto mem = mem_handle.get();

  const auto orig_bytes = _breakpoints.at(address);
  *mem = orig_bytes;

  _breakpoints.erase(_breakpoints.find(address));
}

void Debugger::insert_watchpoint(Address address, uint32_t bytes, xenmem_access_t access) {
  throw FeatureNotSupportedException("insert watchpoint");
}

void Debugger::remove_watchpoint(Address address, uint32_t bytes, xenmem_access_t access) {
  throw FeatureNotSupportedException("remove watchpoint");
}

xd::dbg::MaskedMemory Debugger::read_memory_masking_breakpoints(Address address, size_t length) {
  const auto mem_handle = _domain->map_memory<char>(
      address, length, PROT_READ);
  const auto mem_masked = (unsigned char*)malloc(length);
  memcpy(mem_masked, mem_handle.get(), length);

  const auto address_end = address + length;
  for (const auto [bp_address, bp_orig_bytes] : _breakpoints) {
    if (bp_address >= address && bp_address < address_end) {
      const auto dist = bp_address - address;
      *((uint16_t*)(mem_masked + dist)) = bp_orig_bytes;
    }
  }

  return MaskedMemory(mem_masked);
}

void Debugger::write_memory_retaining_breakpoints(Address address, size_t length, void *data) {
  const auto half_overlap_start_address = address-1;
  const auto half_overlap_end_address = address+length-1;

  const auto length_orig = length;
  if (_breakpoints.count(half_overlap_start_address)) {
    address -= 1;
    length += 1;
  }
  if (_breakpoints.count(half_overlap_end_address))
    length += 1;

  std::vector<xen::Address> bp_addresses;
  const auto address_end = address + length_orig;
  for (const auto [bp_address, _] : _breakpoints) {
    if (bp_address >= address && bp_address < address_end) {
      remove_breakpoint(bp_address);
      bp_addresses.push_back(bp_address);
    }
  }

  const auto mem_handle = _domain->map_memory<char>(address, length, PROT_WRITE);
  const auto mem_orig = (char*)mem_handle.get() + (length - length_orig);
  memcpy((void*)mem_orig, data, length_orig);

  spdlog::get(LOGNAME_ERROR)->info("Wrote {0:d} bytes to {1:x}.", length_orig, address);

  for (const auto &bp_address : bp_addresses)
    insert_breakpoint(bp_address);
}
