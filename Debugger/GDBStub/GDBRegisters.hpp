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
  template <typename T1, typename T2>
  struct _GDBRegisters64 {
    using ValueType1 = T1;
    using ValueType2 = T2;

    ValueType1 rax;
    ValueType1 rbx;
    ValueType1 rcx;
    ValueType1 rdx;
    ValueType1 rsi;
    ValueType1 rdi;
    ValueType1 rbp;
    ValueType1 rsp;

    ValueType1 r8;
    ValueType1 r9;
    ValueType1 r10;
    ValueType1 r11;
    ValueType1 r12;
    ValueType1 r13;
    ValueType1 r14;
    ValueType1 r15;

    ValueType1 rip;

    ValueType1 rflags; 

    ValueType2 cs;
    ValueType2 ss;
    ValueType2 ds;
    ValueType2 es;
    ValueType2 fs;
    ValueType2 gs;
  };

  using GDBRegisters64Values = _GDBRegisters64<uint64_t, uint32_t>;
  using GDBRegisters64Flags = _GDBRegisters64<bool, bool>;

  struct GDBRegisters64 {
    GDBRegisters64Values values;
    GDBRegisters64Flags flags;
  };

  using GDBRegisters = std::variant<GDBRegisters32, GDBRegisters64>;

}

#endif //XENDBG_GDBREGISTERS_HPP
