
//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_X86_64_HPP
#define XENDBG_REGISTERS_X86_64_HPP

#include "Register.hpp"
#include "RegisterContext.hpp"

namespace reg::x86_64 {

  DECLARE_REGISTER(rax,    uint64_t, 0);
  DECLARE_REGISTER(rdx,    uint64_t, 1);
  DECLARE_REGISTER(rcx,    uint64_t, 2);
  DECLARE_REGISTER(rbx,    uint64_t, 3);
  DECLARE_REGISTER(rsi,    uint64_t, 4);
  DECLARE_REGISTER(rdi,    uint64_t, 5);
  DECLARE_REGISTER(rbp,    uint64_t, 6);
  DECLARE_REGISTER(rsp,    uint64_t, 7);
  DECLARE_REGISTER(r8,     uint64_t, 8);
  DECLARE_REGISTER(r9,     uint64_t, 9);
  DECLARE_REGISTER(r10,    uint64_t, 10);
  DECLARE_REGISTER(r11,    uint64_t, 11);
  DECLARE_REGISTER(r12,    uint64_t, 12);
  DECLARE_REGISTER(r13,    uint64_t, 13);
  DECLARE_REGISTER(r14,    uint64_t, 14);
  DECLARE_REGISTER(r15,    uint64_t, 15);
  DECLARE_REGISTER(rip,    uint64_t, 16);
  DECLARE_REGISTER(rflags, uint64_t, 17);
  DECLARE_REGISTER(fs,     uint16_t, -1);
  DECLARE_REGISTER(gs,     uint16_t, -1);
  DECLARE_REGISTER(cs,     uint16_t, -1);
  DECLARE_REGISTER(ds,     uint16_t, -1);
  DECLARE_REGISTER(ss,     uint16_t, -1);

  using RegistersX86_64 = RegisterContext<
    rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi,
    r8, r9, r10, r11, r12, r13, r14, r15,
    rip, rflags, cs, fs, gs, ds, ss>; 

}

#endif //XENDBG_REGISTERS_X86_64_HPP
