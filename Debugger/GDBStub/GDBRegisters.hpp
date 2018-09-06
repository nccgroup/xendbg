//
// Created by Spencer Michaels on 9/6/18.
//

#ifndef XENDBG_GDBREGISTERS_HPP
#define XENDBG_GDBREGISTERS_HPP

#include <cstdint>
#include <variant>

namespace xd::dbg::gdbstub {

  // from gdbserver's regformats/reg-i386-linux.dat
  template <typename T>
  struct _GDBRegisters32 {
    using ValueType = T;

    ValueType eax;
    ValueType ecx;
    ValueType edx;
    ValueType ebx;
    ValueType esp;
    ValueType ebp;
    ValueType esi;
    ValueType edi;
    ValueType eip;
    ValueType eflags;
    ValueType cs;
    ValueType ss;
    ValueType ds;
    ValueType es;
    ValueType fs;
    ValueType gs;
  };  

  using GDBRegisters32Values = _GDBRegisters32<uint32_t>;
  using GDBRegisters32Flags = _GDBRegisters32<bool>;

  struct GDBRegisters32 {
    GDBRegisters32Values values;
    GDBRegisters32Flags flags;
  };

  // from gdbserver's regformats/reg-x86-64.dat
  template <typename T>
  struct _GDBRegisters64 {
    using ValueType = T;

    ValueType rax;
    ValueType rbx;
    ValueType rcx;
    ValueType rdx;
    ValueType rsi;
    ValueType rdi;
    ValueType rbp;
    ValueType rsp;
    ValueType r8;
    ValueType r9;
    ValueType r10;
    ValueType r11;
    ValueType r12;
    ValueType r13;
    ValueType r14;
    ValueType r15;
    ValueType rip;
    ValueType rflags;
    ValueType cs;
    ValueType ss;
    ValueType ds;
    ValueType es;
    ValueType fs;
    ValueType gs;
  };

  using GDBRegisters64Values = _GDBRegisters32<uint32_t>;
  using GDBRegisters64Flags = _GDBRegisters32<bool>;

  struct GDBRegisters64 {
    GDBRegisters64Values values;
    GDBRegisters64Flags flags;
  };

  using GDBRegisters = std::variant<GDBRegisters32, GDBRegisters64>;

}

#endif //XENDBG_GDBREGISTERS_HPP
