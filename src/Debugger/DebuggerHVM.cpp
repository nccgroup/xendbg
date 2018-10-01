#include <Debugger/DebuggerHVM.hpp>

using xd::xen::Address;
using xd::dbg::Debugger;
using xd::dbg::DebuggerHVM;

DebuggerHVM::DebuggerHVM(uvw::Loop &loop, xen::DomainHVM &domain)
  : Debugger(loop, domain), _domain(domain)
{
}

void DebuggerHVM::continue_() {

}

Address DebuggerHVM::single_step() {

}

std::optional<Address> DebuggerHVM::check_breakpoint_hit() {

}

void DebuggerHVM::cleanup() {
  for (const auto &il : _breakpoints)
    remove_breakpoint(il.first);
}

void DebuggerHVM::insert_breakpoint(xen::Address address) {
}

void DebuggerHVM::remove_breakpoint(xen::Address address) {

}

Debugger::MaskedMemory DebuggerHVM::read_memory_masking_breakpoints(
    Address address, size_t length)
{

}

void DebuggerHVM::write_memory_retaining_breakpoints(
    Address address, size_t length, void *data)
{

}
