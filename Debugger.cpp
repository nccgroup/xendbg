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
  _current_vcpu = 0;
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
