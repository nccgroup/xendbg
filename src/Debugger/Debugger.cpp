#include <Debugger/Debugger.hpp>

using xd::xen::Address;
using xd::xen::Domain;
using xd::dbg::Debugger;

Debugger::Debugger(xen::Domain &domain)
    : _domain(domain), _vcpu_id(0), _is_attached(false),
      _last_stop_reason(StopReasonBreakpoint(SIGSTOP, 0))
{
}

Debugger::~Debugger() {
  if (_is_attached)
    this->detach();
}

void Debugger::attach() {
  _is_attached = true;
  _domain.pause();
}

void Debugger::detach() {
  _domain.pause();
  cleanup();
  _domain.unpause_all_vcpus();
  _domain.unpause();
  _is_attached = false;
}

void Debugger::did_stop(StopReason reason) {
  _last_stop_reason = reason;
  if (_on_stop)
    _on_stop(reason);
}

void Debugger::cleanup() {
  for (auto it = _breakpoints.cbegin(); it != _breakpoints.cend();)
    it = remove_breakpoint(it->first);
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

  const auto mem_handle = _domain.map_memory<uint8_t>(
      address, sizeof(uint8_t), PROT_READ | PROT_WRITE);
  const auto mem = mem_handle.get();

  const auto orig_bytes = *mem;

  _breakpoints[address] = orig_bytes;
  *mem = X86_INT3;
}

Debugger::BreakpointMap::iterator Debugger::remove_breakpoint(Address address) {
  spdlog::get(LOGNAME_CONSOLE)->debug("Removing breakpoint at {0:x}", address);

  if (!_breakpoints.count(address)) {
    spdlog::get(LOGNAME_ERROR)->info(
        "[!]: Tried to remove infinite loop where one does not exist. "
        "This is generally harmless, but might indicate a failure in estimating the "
        "next instruction address.",
        address);
    return _breakpoints.end();
  }

  const auto mem_handle = _domain.map_memory<uint8_t>(
      address, sizeof(uint8_t), PROT_WRITE);
  const auto mem = mem_handle.get();

  const auto orig_bytes = _breakpoints.at(address);
  *mem = orig_bytes;

  return _breakpoints.erase(_breakpoints.find(address));
}

void Debugger::insert_watchpoint(Address address, uint32_t bytes, WatchpointType type) {
  throw FeatureNotSupportedException("insert watchpoint");
}

void Debugger::remove_watchpoint(Address address, uint32_t bytes, WatchpointType type) {
  throw FeatureNotSupportedException("remove watchpoint");
}

xd::dbg::MaskedMemory Debugger::read_memory_masking_breakpoints(Address address, size_t length) {
  const auto mem_handle = _domain.map_memory<char>(
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

  const auto mem_handle = _domain.map_memory<char>(address, length, PROT_WRITE);
  const auto mem_orig = (char*)mem_handle.get() + (length - length_orig);
  memcpy((void*)mem_orig, data, length_orig);

  spdlog::get(LOGNAME_ERROR)->info("Wrote {0:d} bytes to {1:x}.", length_orig, address);

  for (const auto &bp_address : bp_addresses)
    insert_breakpoint(bp_address);
}
