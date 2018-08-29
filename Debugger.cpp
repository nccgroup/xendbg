//
// Created by Spencer Michaels on 8/28/18.
//

#include <stdexcept>

#include "Debugger.hpp"

using xd::Debugger;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Debugger::Debugger()
{
}

Domain& Debugger::attach(DomID domid) {
  _domain.emplace(_xen, domid);
  return _domain.value();
}

void Debugger::detach() {
  _domain.reset();
}

