//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include <capstone/capstone.h>
#include <elfio/elfio.hpp>

#include "Debugger.hpp"
#include "../Util/overloaded.hpp"

#define X86_MAX_INSTRUCTION_SIZE 0x10
#define X86_INFINITE_LOOP 0xFEEB

using xd::dbg::Debugger;
using xd::dbg::NoSuchSymbolException;
using xd::dbg::NoSuchVariableException;
using xd::xen::Address;
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
  _domain->pause();
  const auto bp = insert_breakpoint(address);
  _domain->unpause();
  _breakpoints[bp.id] = bp;
  return bp.id;
}

void Debugger::delete_breakpoint(size_t id) {
  if (!_domain)
    throw NoGuestAttachedException();

  if (_breakpoints.count(id) == 0)
    throw NoSuchBreakpointException(id);

  const auto &bp = _breakpoints.at(id);
  _domain->pause();
  remove_breakpoint(bp);
  _domain->unpause();
  _breakpoints.erase(_breakpoints.find(id));
}

Debugger::Breakpoint Debugger::continue_until_breakpoint() {
  if (!_domain)
    throw NoGuestAttachedException();

  // If we're already at a breakpoint, step past it and put it back
  std::optional<Breakpoint> bp;
  if ((bp = check_breakpoint_hit(*_domain))) {
    remove_breakpoint(*bp);
    single_step();
    insert_breakpoint(bp->address);
  }

  _domain->unpause();
  while (!(bp = check_breakpoint_hit(*_domain)));
  _domain->pause();

  return *bp;
}

void Debugger::single_step() {
  if (!_domain)
    throw NoGuestAttachedException();

  _domain->pause();

  // For conditional branches, we need to insert BPs at both potential locations.
  const auto [addr1, addr2] = get_address_of_next_instruction(*_domain);

  Breakpoint bp1, bp2;
  if (addr1)
      bp1 = insert_breakpoint(addr1);
  if (addr2)
      bp2 = insert_breakpoint(addr2);

  _domain->unpause();

  while (!(check_infinite_loop_hit(*_domain)));

  _domain->pause();

  if (addr1)
      remove_breakpoint(bp1);
  if (addr2)
      remove_breakpoint(bp2);
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

std::optional<Debugger::Breakpoint> Debugger::check_breakpoint_hit(
    const xen::Domain &domain)
{
  const auto address = check_infinite_loop_hit(domain);
  if (!address)
    return std::nullopt;

  const auto found = std::find_if(_breakpoints.begin(), _breakpoints.end(),
    [address](const auto &pair) {
      return pair.second.address == address;
    });

  if (found == _breakpoints.end())
    return std::nullopt;

  return found->second;
}

xd::xen::Address Debugger::check_infinite_loop_hit(const xen::Domain &domain) {
  const auto address = std::visit(util::overloaded {
    [](const xen::Registers32 regs) {
      return (uint64_t)regs.eip;
    },
    [](const xen::Registers64 regs) {
      return (uint64_t)regs.rip;
    }
  }, domain.get_cpu_context(_current_vcpu));

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ);
  const auto mem = (uint16_t*)mem_handle.get();

  return (*mem == X86_INFINITE_LOOP) ? address : 0;
}

std::pair<Address, Address> Debugger::get_address_of_next_instruction(
    const xen::Domain &domain)
{
  const auto mode =
    (domain.get_word_size() == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

  const auto address = std::visit(util::overloaded {
    [](const xen::Registers32 regs) {
      return (uint64_t)regs.eip;
    },
    [](const xen::Registers64 regs) {
      return (uint64_t)regs.rip;
    }
  }, domain.get_cpu_context(_current_vcpu));

  const auto read_size = (2*X86_MAX_INSTRUCTION_SIZE);
  const auto mem_handle = _domain->map_memory(address, read_size, PROT_READ);
  const auto mem = (uint8_t*)mem_handle.get();

  csh handle;
  cs_insn *instrs;
	size_t instrs_size;
  if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
    throw std::runtime_error("Failed to open Capstone handle!");

  instrs_size = cs_disasm(handle, mem, read_size-1,
      address, 0, &instrs);

  if (instrs_size < 2)
    throw std::runtime_error("Failed to read instructions!");

  auto cur_instr = instrs[0];
  const auto next_instr_address = instrs[1].address;

  std::pair<Address, Address> ret;
  if (cs_insn_group(handle, &cur_instr, X86_GRP_JUMP)) {
    ret = std::make_pair(next_instr_address, X86_REL_ADDR(cur_instr));
  } else if (cs_insn_group(handle, &cur_instr, X86_GRP_CALL)) {
    ret = std::make_pair(0, X86_REL_ADDR(cur_instr));
  } else if (cs_insn_group(handle, &cur_instr, X86_GRP_RET)) {
    ret = std::make_pair(0, X86_REL_ADDR(cur_instr));
  } else {
    ret = std::make_pair(next_instr_address, 0);
  }

  cs_close(&handle);
  return ret;
}

Debugger::Breakpoint Debugger::insert_breakpoint(xen::Address address) {
  if (!_domain)
    throw NoGuestAttachedException();

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ | PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  const auto id = _next_breakpoint_id++;
  const auto orig_bytes = *mem;

  *mem = X86_INFINITE_LOOP;

  return Breakpoint{ id, address, orig_bytes };
}

void Debugger::remove_breakpoint(const Breakpoint &bp) {
  const auto mem_handle = _domain->map_memory(bp.address, 2, PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  *mem = bp.orig_bytes;
}
