//
// Created by Spencer Michaels on 8/28/18.
//

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
  auto regs = _domain.value().get_cpu_context(_current_cpu);

  std::visit(util::overloaded {
    [&name](const xen::Registers32 regs) {
      regs.for_each([&name](const auto &reg_name, auto val) {
        if (reg_name == name)
          return val;
      });
    },
    [&name](const xen::Registers64 regs) {
      regs.for_each([&name](const auto &reg_name, auto val) {
        if (reg_name == name)
          return val;
      });
    }
  }, regs);

  return _variables.at(name);
}

void Debugger::set_var(const std::string &name, uint64_t value) {
  if (_variables.count(name) == 1) {
    _variables.at(name) = value;
    return;
  }

  auto regs = _domain.value().get_cpu_context(_current_cpu);
  std::visit(util::overloaded {
    [&name, value](xen::Registers32& regs) {
      regs.set_by_name(name, value);
      // TODO: set CPU context
    },
    [&name, value](xen::Registers64& regs) {
      regs.set_by_name(name, value);
      // TODO: set CPU context
    }
  }, regs);
}
