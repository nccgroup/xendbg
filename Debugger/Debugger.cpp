//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include <elfio/elfio.hpp>

#include "Debugger.hpp"
#include "../Util/overloaded.hpp"

using xd::dbg::Debugger;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Domain& Debugger::attach(DomID domid) {
  _current_vcpu = 0;
  _domain.emplace(_xen, domid);
  _domain.value().set_debugging(true);

  return _domain.value();
}

void Debugger::detach() {
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
  return _symbols.at(name);
}

uint64_t Debugger::get_var(const std::string &name) {
  return _variables.at(name);
}

void Debugger::set_var(const std::string &name, uint64_t value) {
  _variables[name] = value;
}

void Debugger::delete_var(const std::string &name) {
  if (!_variables.count(name))
    // TODO
    throw std::runtime_error("No such variable!");
  _variables.erase(name);
}
