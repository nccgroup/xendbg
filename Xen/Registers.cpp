//
// Created by Spencer Michaels on 8/29/18.
//

#include <set>
#include <unordered_map>
#include <vector>

#include "XenException.hpp"
#include "../Util/overloaded.hpp"
#include "Registers.hpp"

using xd::xen::Registers32;
using xd::xen::Registers64;

template <typename Regs_t>
using GetByNameMap = std::unordered_map<std::string,
  std::function<typename Regs_t::ValueType(const Regs_t &)>>;

template <typename Regs_t>
using SetByNameMap = std::unordered_map<std::string,
  std::function<void(Regs_t &, typename Regs_t::ValueType)>>;

Registers32::ValueType Registers32::get(const std::string &name) const {
  const auto &names = Registers32::names;

  const auto found = std::find_if(names.begin(), names.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  if (found == names.end())
    throw xen::XenException("No such register: " + name);

  const auto id = std::distance(names.begin(), found);
  return get(id);
}

Registers32::ValueType Registers32::get(size_t id) const {
  using T = Registers32::ValueType;
  using V = std::vector<std::function<T(const Registers32&)>>;

  static const V get_by_id = {
    [](const auto &regs) { return (T)regs.eax; },
    [](const auto &regs) { return (T)regs.ebx; },
    [](const auto &regs) { return (T)regs.ecx; },
    [](const auto &regs) { return (T)regs.edx; },
    [](const auto &regs) { return (T)regs.edi; },
    [](const auto &regs) { return (T)regs.esi; },
    [](const auto &regs) { return (T)regs.ebp; },
    [](const auto &regs) { return (T)regs.esp; },
    [](const auto &regs) { return (T)regs.ss; },
    [](const auto &regs) { return (T)regs.eip; },
    [](const auto &regs) { return (T)regs.eflags; },
    [](const auto &regs) { return (T)regs.cs; },
    [](const auto &regs) { return (T)regs.ds; },
    [](const auto &regs) { return (T)regs.es; },
    [](const auto &regs) { return (T)regs.fs; },
    [](const auto &regs) { return (T)regs.gs; }
  };

  if (id < get_by_id.size())
    return get_by_id.at(id)(*this);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

void Registers32::set(const std::string &name, ValueType value) {
  const auto &names = Registers32::names;

  const auto found = std::find_if(names.begin(), names.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  if (found == names.end())
    throw xen::XenException("No such register: " + name);

  const auto id = std::distance(names.begin(), found);
  return set(id, value);
}

void Registers32::set(size_t id, ValueType value) {
  using V = std::vector<std::function<void(Registers32&, ValueType)>>;

  static const V set_by_id = {
    [](auto &regs, auto value) { regs.eax = value; },
    [](auto &regs, auto value) { regs.ebx = value; },
    [](auto &regs, auto value) { regs.ecx = value; },
    [](auto &regs, auto value) { regs.edx = value; },
    [](auto &regs, auto value) { regs.edi = value; },
    [](auto &regs, auto value) { regs.esi = value; },
    [](auto &regs, auto value) { regs.ebp = value; },
    [](auto &regs, auto value) { regs.esp = value; },
    [](auto &regs, auto value) { regs.ss = value; },
    [](auto &regs, auto value) { regs.eip = value; },
    [](auto &regs, auto value) { regs.eflags = value; },
    [](auto &regs, auto value) { regs.cs = value; },
    [](auto &regs, auto value) { regs.ds = value; },
    [](auto &regs, auto value) { regs.es = value; },
    [](auto &regs, auto value) { regs.fs = value; },
    [](auto &regs, auto value) { regs.gs = value; }
  };

  if (id < set_by_id.size())
    return set_by_id.at(id)(*this, value);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

std::string Registers32::get_name_by_id(size_t id) {
  const auto &names = Registers32::names;
  if (id < names.size())
    return *(names.begin()+id);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

bool Registers32::is_valid_id(size_t id) {
  return (id < Registers32::names.size());
}

Registers64::ValueType Registers64::get(const std::string &name) const {
  const auto &names = Registers64::names;

  const auto found = std::find_if(names.begin(), names.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  if (found == names.end())
    throw xen::XenException("No such register: " + name);

  const auto id = std::distance(names.begin(), found);
  return get(id);
}

Registers64::ValueType Registers64::get(size_t id) const {
  using T = Registers64::ValueType;
  using V = std::vector<std::function<T(const Registers64&)>>;

  static const V get_by_id = {
      [](const auto &regs) { return regs.rax; },
      [](const auto &regs) { return regs.rbx; },
      [](const auto &regs) { return regs.rcx; },
      [](const auto &regs) { return regs.rdx; },
      [](const auto &regs) { return regs.rsp; },
      [](const auto &regs) { return regs.rbp; },
      [](const auto &regs) { return regs.rsi; },
      [](const auto &regs) { return regs.rdi; },
      [](const auto &regs) { return regs.r8; },
      [](const auto &regs) { return regs.r9; },
      [](const auto &regs) { return regs.r10; },
      [](const auto &regs) { return regs.r11; },
      [](const auto &regs) { return regs.r12; },
      [](const auto &regs) { return regs.r13; },
      [](const auto &regs) { return regs.r14; },
      [](const auto &regs) { return regs.r15; },
      [](const auto &regs) { return regs.rip; },
      [](const auto &regs) { return regs.rflags; },
      [](const auto &regs) { return regs.fs; },
      [](const auto &regs) { return regs.gs; },
      [](const auto &regs) { return regs.cs; },
      [](const auto &regs) { return regs.ds; },
      [](const auto &regs) { return regs.ss; },
  };

  if (id < get_by_id.size())
    return get_by_id.at(id)(*this);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

void Registers64::set(const std::string &name, ValueType value) {
  const auto &names = Registers64::names;

  const auto found = std::find_if(names.begin(), names.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  if (found == names.end())
    throw xen::XenException("No such register: " + name);

  const auto id = std::distance(names.begin(), found);
  return set(id, value);
}

void Registers64::set(size_t id, ValueType value) {
  using V = std::vector<std::function<void(Registers64&, ValueType value)>>;

  static const V set_by_id = {
      [](auto &regs, auto value) { regs.rax = value; },
      [](auto &regs, auto value) { regs.rbx = value; },
      [](auto &regs, auto value) { regs.rcx = value; },
      [](auto &regs, auto value) { regs.rdx = value; },
      [](auto &regs, auto value) { regs.rsp = value; },
      [](auto &regs, auto value) { regs.rbp = value; },
      [](auto &regs, auto value) { regs.rsi = value; },
      [](auto &regs, auto value) { regs.rdi = value; },
      [](auto &regs, auto value) { regs.r8 = value; },
      [](auto &regs, auto value) { regs.r9 = value; },
      [](auto &regs, auto value) { regs.r10 = value; },
      [](auto &regs, auto value) { regs.r11 = value; },
      [](auto &regs, auto value) { regs.r12 = value; },
      [](auto &regs, auto value) { regs.r13 = value; },
      [](auto &regs, auto value) { regs.r14 = value; },
      [](auto &regs, auto value) { regs.r15 = value; },
      [](auto &regs, auto value) { regs.rip = value; },
      [](auto &regs, auto value) { regs.rflags = value; },
      [](auto &regs, auto value) { regs.fs = value; },
      [](auto &regs, auto value) { regs.gs = value; },
      [](auto &regs, auto value) { regs.cs = value; },
      [](auto &regs, auto value) { regs.ds = value; },
      [](auto &regs, auto value) { regs.ss = value; },
  };

  if (id < set_by_id.size())
    return set_by_id.at(id)(*this, value);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

std::string Registers64::get_name_by_id(size_t id) {
  const auto &names = Registers64::names;
  if (id < names.size())
    return *(names.begin()+id);
  throw xen::XenException("No register with ID " + std::to_string(id));
}

bool Registers64::is_valid_id(size_t id) {
  return (id < Registers64::names.size());
}

uint64_t xd::xen::get_register(const Registers &regs,
        const std::string &name)
{
  return std::visit(util::overloaded {
    [&name](const xen::Registers32& regs) {
      return (uint64_t)regs.get(name);
    },
    [&name](const xen::Registers64& regs) {
      return (uint64_t)regs.get(name);
    }
  }, regs);
}

uint64_t xd::xen::get_register(const Registers &regs, size_t id) {
  return std::visit(util::overloaded {
    [&id](const xen::Registers32& regs) {
      return (uint64_t)regs.get(id);
    },
    [&id](const xen::Registers64& regs) {
      return (uint64_t)regs.get(id);
    }
  }, regs);
}

void xd::xen::set_register(Registers &regs, const std::string &name,
        uint64_t value)
{
  std::visit(util::overloaded {
    [&name, value](xen::Registers32& regs) {
      regs.set(name, value);
    },
    [&name, value](xen::Registers64& regs) {
      regs.set(name, value);
    }
  }, regs);
}

void xd::xen::set_register(Registers &regs, size_t name, uint64_t value) {
  std::visit(util::overloaded {
    [&name, value](xen::Registers32& regs) {
      regs.set(name, value);
    },
    [&name, value](xen::Registers64& regs) {
      regs.set(name, value);
    }
  }, regs);
}

bool xd::xen::is_register_name(const std::string &name) {
  const auto &names32 = Registers32::names;
  const auto &names64 = Registers64::names;

  const auto found32 = std::find_if(names32.begin(), names32.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  const auto found64 = std::find_if(names64.begin(), names64.end(),
    [&name](const auto &candidate) {
      return candidate == name;
    });

  return (found64 != names64.end()) || (found32 != names32.end());
}
