//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include "Debugger.hpp"
#include "Util/overloaded.hpp"

using xd::Debugger;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Domain& Debugger::attach(DomID domid) {
  _current_cpu = 0;
  _domain.emplace(_xen, domid);
  return _domain.value();
}

void Debugger::detach() {
  _domain.reset();
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

uint64_t Debugger::get_var(const std::string &name) {
  if (_variables.count(name) > 0)
    return _variables.at(name);

  const auto regs = _domain.value().get_cpu_context(_current_cpu);

  return std::visit(util::overloaded {
    [&name](const xen::Registers32 regs) {
      return (uint64_t)regs.get_by_name(name);
    },
    [&name](const xen::Registers64 regs) {
      return (uint64_t)regs.get_by_name(name);
    }
  }, regs);
}

void Debugger::set_var(const std::string &name, uint64_t value) {
  auto regs = _domain.value().get_cpu_context(_current_cpu);

  try {
    std::visit(util::overloaded {
      [this, &name, value](xen::Registers32& regs) {
        regs.set_by_name(name, value);
        _domain.value().set_cpu_context(regs);
      },
      [this, &name, value](xen::Registers64& regs) {
        regs.set_by_name(name, value);
        _domain.value().set_cpu_context(regs);
      }
    }, regs);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
  }

  _variables[name] = value;
}

void Debugger::delete_var(const std::string &name) {
  if (!_variables.count(name))
    // TODO
    throw std::runtime_error("No such variable!");
  _variables.erase(name);
}
