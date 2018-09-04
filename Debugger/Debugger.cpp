//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include <elfio/elfio.hpp>

#include "Debugger.hpp"
#include "../Util/overloaded.hpp"

#define INFINITE_LOOP_X86 0xFEEB

using xd::dbg::Debugger;
using xd::dbg::NoSuchSymbolException;
using xd::dbg::NoSuchVariableException;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Domain& Debugger::attach(DomID domid) {
  _current_vcpu = 0;
  _next_breakpoint_id = 0;
  _domain.emplace(_xen, domid);
  _domain->set_debugging(true);

  return _domain.value();
}

void Debugger::detach() {
  for (const auto &bp : _breakpoints) {
    delete_breakpoint(bp.first);
  }

  _symbols.clear();
  _variables.clear();
  _domain.reset();
}

void Debugger::load_symbols_from_file(const std::string &name) {
  ELFIO::elfio reader;

  if (!reader.load(name))
    throw std::runtime_error("Failed to read file!");

  _symbols.clear();

  for (const auto section : reader.sections) {
    if (section->get_type() == SHT_SYMTAB) {
      const ELFIO::symbol_section_accessor symbols(reader, section);
      const size_t num_symbols = symbols.get_symbols_num();
      for (size_t i = 0; i < num_symbols; ++i) {
        std::string       name;
        ELFIO::Elf64_Addr address;
        ELFIO::Elf_Xword  size;
        unsigned char     bind;
        unsigned char     type;
        ELFIO::Elf_Half   section_index;
        unsigned char     other;

        symbols.get_symbol(i, name, address, size, bind, type, section_index, other);

        // TODO: very basic for now
        if (type == STT_FUNC && address > 0)
          _symbols[name] = Symbol{address};
      }
    }
  }
}

size_t Debugger::create_breakpoint(xen::Address address) {
  if (!_domain)
    throw NoGuestAttachedException();

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ | PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  const auto id = _next_breakpoint_id++;
  const auto orig_bytes = *mem;

  _domain->pause();
  _breakpoints[id] = Breakpoint{ id, address, orig_bytes };
  *mem = INFINITE_LOOP_X86;
  _domain->unpause();

  return id;
}

void Debugger::delete_breakpoint(size_t id) {
  if (!_domain)
    throw NoGuestAttachedException();

  if (_breakpoints.count(id) == 0)
    throw NoSuchBreakpointException(id);
  const auto &bp = _breakpoints.at(id);

  const auto mem_handle = _domain->map_memory(bp.address, 2, PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  _domain->pause();
  *mem = bp.orig_bytes;
  _breakpoints.erase(_breakpoints.find(id));
  _domain->unpause();
}

Debugger::Breakpoint Debugger::continue_until_breakpoint() {
  if (!_domain)
    throw NoGuestAttachedException();

  _domain->unpause();

  std::optional<Breakpoint> bp;
  while (!(bp = check_breakpoint_hit()));

  _domain->pause();

  return *bp;
}

std::vector<Domain> Debugger::get_guest_domains() {
  const auto domids = _xen.get_xenstore().get_guest_domids();

  std::vector<Domain> domains;
  domains.reserve(domids.size());
  std::transform(domids.begin(), domids.end(), std::back_inserter(domains),
    [this](const auto& domid) {
      return Domain(_xen, domid);
    });
  return domains;
}

const Debugger::Symbol &Debugger::lookup_symbol(const std::string &name) {
  if (!_symbols.count(name))
    throw NoSuchSymbolException(name);
  return _symbols.at(name);
}

uint64_t Debugger::get_var(const std::string &name) {
  if (!_variables.count(name))
    throw NoSuchSymbolException(name);
  return _variables.at(name);
}

void Debugger::set_var(const std::string &name, uint64_t value) {
  _variables[name] = value;
}

void Debugger::delete_var(const std::string &name) {
  if (!_variables.count(name))
    throw NoSuchVariableException("No such variable!");
  _variables.erase(name);
}

std::optional<Debugger::Breakpoint> Debugger::check_breakpoint_hit() {
  if (!_domain)
    throw NoGuestAttachedException();

  const auto address = std::visit(util::overloaded {
    [](const xen::Registers32 regs) {
      return (uint64_t)regs.eip;
    },
    [](const xen::Registers64 regs) {
      return (uint64_t)regs.rip;
    }
  }, _domain->get_cpu_context(_current_vcpu));

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ);
  const auto mem = (uint16_t*)mem_handle.get();

  if (*mem != INFINITE_LOOP_X86)
    return std::nullopt;

  const auto found = std::find_if(_breakpoints.begin(), _breakpoints.end(),
    [address](const auto &pair) {
      return pair.second.address == address;
    });

  if (found == _breakpoints.end())
    return std::nullopt;

  return found->second;
}
