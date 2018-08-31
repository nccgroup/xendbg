//
// Created by Spencer Michaels on 8/29/18.
//

#include <set>
#include <unordered_map>

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

Registers32::ValueType Registers32::get_by_name(const std::string &name) const {
  static const GetByNameMap<Registers32> get_by_name_map = {
    { "eax",    [](auto &regs) { return regs.eax; } },
    { "ebx",    [](auto &regs) { return regs.ebx; } },
    { "ecx",    [](auto &regs) { return regs.ecx; } },
    { "edx",    [](auto &regs) { return regs.edx; } },
    { "edi",    [](auto &regs) { return regs.edi; } },
    { "esi",    [](auto &regs) { return regs.esi; } },
    { "ebp",    [](auto &regs) { return regs.ebp; } },
    { "esp",    [](auto &regs) { return regs.esp; } },
    { "ss",     [](auto &regs) { return regs.ss; } },
    { "eflags", [](auto &regs) { return regs.eflags; } },
    { "eip",    [](auto &regs) { return regs.eip; } },
    { "cs",     [](auto &regs) { return regs.cs; } },
    { "ds",     [](auto &regs) { return regs.ds; } },
    { "es",     [](auto &regs) { return regs.es; } },
    { "fs",     [](auto &regs) { return regs.fs; } },
    { "gs",     [](auto &regs) { return regs.gs; } },
  };

  return get_by_name_map.at(name)(*this);
}

void Registers32::set_by_name(const std::string &name, ValueType value) {
  static const SetByNameMap<Registers32> set_by_name_map = {
    { "eax",    [](auto &regs, auto value) { regs.eax = value; } },
    { "ebx",    [](auto &regs, auto value) { regs.ebx = value; } },
    { "ecx",    [](auto &regs, auto value) { regs.ecx = value; } },
    { "edx",    [](auto &regs, auto value) { regs.edx = value; } },
    { "edi",    [](auto &regs, auto value) { regs.edi = value; } },
    { "esi",    [](auto &regs, auto value) { regs.esi = value; } },
    { "ebp",    [](auto &regs, auto value) { regs.ebp = value; } },
    { "esp",    [](auto &regs, auto value) { regs.esp = value; } },
    { "ss",     [](auto &regs, auto value) { regs.ss = value; } },
    { "eflags", [](auto &regs, auto value) { regs.eflags = value; } },
    { "eip",    [](auto &regs, auto value) { regs.eip = value; } },
    { "cs",     [](auto &regs, auto value) { regs.cs = value; } },
    { "ds",     [](auto &regs, auto value) { regs.ds = value; } },
    { "es",     [](auto &regs, auto value) { regs.es = value; } },
    { "fs",     [](auto &regs, auto value) { regs.fs = value; } },
    { "gs",     [](auto &regs, auto value) { regs.gs = value; } },
  };

  return set_by_name_map.at(name)(*this, value);
}

Registers64::ValueType Registers64::get_by_name(const std::string &name) const {
  static const GetByNameMap<Registers64> get_by_name_map = {
      { "rax",    [](auto &regs) { return regs.rax; } },
      { "rbx",    [](auto &regs) { return regs.rbx; } },
      { "rcx",    [](auto &regs) { return regs.rcx; } },
      { "rdx",    [](auto &regs) { return regs.rdx; } },
      { "rsp",    [](auto &regs) { return regs.rsp; } },
      { "rbp",    [](auto &regs) { return regs.rbp; } },
      { "rsi",    [](auto &regs) { return regs.rsi; } },
      { "rdi",    [](auto &regs) { return regs.rdi; } },
      { "r8",     [](auto &regs) { return regs.r8; } },
      { "r9",     [](auto &regs) { return regs.r9; } },
      { "r10",    [](auto &regs) { return regs.r10; } },
      { "r11",    [](auto &regs) { return regs.r11; } },
      { "r12",    [](auto &regs) { return regs.r12; } },
      { "r13",    [](auto &regs) { return regs.r13; } },
      { "r14",    [](auto &regs) { return regs.r14; } },
      { "r15",    [](auto &regs) { return regs.r15; } },
      { "rflags", [](auto &regs) { return regs.rflags; } },
      { "rip",    [](auto &regs) { return regs.rip; } },
      { "fs",     [](auto &regs) { return regs.fs; } },
      { "gs",     [](auto &regs) { return regs.gs; } },
      { "cs",     [](auto &regs) { return regs.cs; } },
      { "ds",     [](auto &regs) { return regs.ds; } },
      { "ss",     [](auto &regs) { return regs.ss; } },
  };

  return get_by_name_map.at(name)(*this);
}

void Registers64::set_by_name(const std::string &name, ValueType value) {
  static const SetByNameMap<Registers64> set_by_name_map = {
      { "rax",    [](auto &regs, auto value) { regs.rax = value; } },
      { "rbx",    [](auto &regs, auto value) { regs.rbx = value; } },
      { "rcx",    [](auto &regs, auto value) { regs.rcx = value; } },
      { "rdx",    [](auto &regs, auto value) { regs.rdx = value; } },
      { "rsp",    [](auto &regs, auto value) { regs.rsp = value; } },
      { "rbp",    [](auto &regs, auto value) { regs.rbp = value; } },
      { "rsi",    [](auto &regs, auto value) { regs.rsi = value; } },
      { "rdi",    [](auto &regs, auto value) { regs.rdi = value; } },
      { "r8",     [](auto &regs, auto value) { regs.r8 = value; } },
      { "r9",     [](auto &regs, auto value) { regs.r9 = value; } },
      { "r10",    [](auto &regs, auto value) { regs.r10 = value; } },
      { "r11",    [](auto &regs, auto value) { regs.r11 = value; } },
      { "r12",    [](auto &regs, auto value) { regs.r12 = value; } },
      { "r13",    [](auto &regs, auto value) { regs.r13 = value; } },
      { "r14",    [](auto &regs, auto value) { regs.r14 = value; } },
      { "r15",    [](auto &regs, auto value) { regs.r15 = value; } },
      { "rflags", [](auto &regs, auto value) { regs.rflags = value; } },
      { "rip",    [](auto &regs, auto value) { regs.rip = value; } },
      { "fs",     [](auto &regs, auto value) { regs.fs = value; } },
      { "gs",     [](auto &regs, auto value) { regs.gs = value; } },
      { "cs",     [](auto &regs, auto value) { regs.cs = value; } },
      { "ds",     [](auto &regs, auto value) { regs.ds = value; } },
      { "ss",     [](auto &regs, auto value) { regs.ss = value; } },
  };

  return set_by_name_map.at(name)(*this, value);
}

uint64_t xd::xen::get_register_by_name(const Registers &regs,
        const std::string &name)
{
  return std::visit(util::overloaded {
    [&name](const xen::Registers32& regs) {
      return (uint64_t)regs.get_by_name(name);
    },
    [&name](const xen::Registers64& regs) {
      return (uint64_t)regs.get_by_name(name);
    }
  }, regs);
}

void xd::xen::set_register_by_name(Registers &regs, const std::string &name,
        uint64_t value)
{
  std::visit(util::overloaded {
    [&name, value](xen::Registers32& regs) {
      regs.set_by_name(name, value);
    },
    [&name, value](xen::Registers64& regs) {
      regs.set_by_name(name, value);
    }
  }, regs);
}

bool xd::xen::is_register_name(const std::string &name) {
  static const std::set<std::string> registers32_name_map = {
    { "eax" },
    { "ebx" },
    { "ecx" },
    { "edx" },
    { "edi" },
    { "esi" },
    { "ebp" },
    { "esp" },
    { "ss" },
    { "eflags" },
    { "eip" },
    { "cs" },
    { "ds" },
    { "es" },
    { "fs" },
    { "gs" },
  };

  static const std::set<std::string> registers64_name_map = {
    { "rax" },
    { "rbx" },
    { "rcx" },
    { "rdx" },
    { "rsp" },
    { "rbp" },
    { "rsi" },
    { "rdi" },
    { "r8" },
    { "r9" },
    { "r10" },
    { "r11" },
    { "r12" },
    { "r13" },
    { "r14" },
    { "r15" },
    { "rflags" },
    { "rip" },
    { "fs" },
    { "gs" },
    { "cs" },
    { "ds" },
    { "ss" },
  };

  return registers32_name_map.count(name) || registers64_name_map.count(name);
}
