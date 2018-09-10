
//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_X86_64_HPP
#define XENDBG_REGISTERS_X86_64_HPP

#include "Registers.hpp"

namespace reg::x86_64 {

  DECLARE_REGISTER(rax,     uint64_t);
  DECLARE_REGISTER(rbx,     uint64_t);
  DECLARE_REGISTER(rcx,     uint64_t);
  DECLARE_REGISTER(rdx,     uint64_t);
  DECLARE_REGISTER(rsp,     uint64_t);
  DECLARE_REGISTER(rbp,     uint64_t);
  DECLARE_REGISTER(rsi,     uint64_t);
  DECLARE_REGISTER(rdi,     uint64_t);
  DECLARE_REGISTER(r8,      uint64_t);
  DECLARE_REGISTER(r9,      uint64_t);
  DECLARE_REGISTER(r10,     uint64_t);
  DECLARE_REGISTER(r11,     uint64_t);
  DECLARE_REGISTER(r12,     uint64_t);
  DECLARE_REGISTER(r13,     uint64_t);
  DECLARE_REGISTER(r14,     uint64_t);
  DECLARE_REGISTER(r15,     uint64_t);
  DECLARE_REGISTER(rip,     uint64_t);
  DECLARE_REGISTER(rflags,  uint64_t);
  DECLARE_REGISTER(fs,      uint16_t);
  DECLARE_REGISTER(gs,      uint16_t);
  DECLARE_REGISTER(cs,      uint16_t);
  DECLARE_REGISTER(ds,      uint16_t);
  DECLARE_REGISTER(ss,      uint16_t);
}

#endif //XENDBG_REGISTERS_X86_64_HPP
