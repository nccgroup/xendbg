
//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_X86_HPP
#define XENDBG_REGISTERS_X86_HPP

#include "Register.hpp"
#include "RegisterContext.hpp"

namespace xd::reg::x86_32 {

  DECLARE_REGISTER(eax,    uint32_t, 0);
  DECLARE_REGISTER(ebx,    uint32_t, 2);
  DECLARE_REGISTER(ecx,    uint32_t, 2);
  DECLARE_REGISTER(edx,    uint32_t, 1);
  DECLARE_REGISTER(esi,    uint32_t, 4);
  DECLARE_REGISTER(edi,    uint32_t, 5);
  DECLARE_REGISTER(ebp,    uint32_t, 6);
  DECLARE_REGISTER(esp,    uint32_t, 7);
  DECLARE_REGISTER(eip,    uint32_t, 8);
  DECLARE_REGISTER(eflags, uint16_t, 9);
  DECLARE_REGISTER(ss,     uint32_t, -1);
  DECLARE_REGISTER(cs,     uint16_t, -1);
  DECLARE_REGISTER(ds,     uint16_t, -1);
  DECLARE_REGISTER(es,     uint16_t, -1);
  DECLARE_REGISTER(fs,     uint16_t, -1);
  DECLARE_REGISTER(gs,     uint16_t, -1);

  // TODO
  DECLARE_REGISTER(cr3,    uint64_t, -1);

  using RegistersX86_32 = RegisterContext<
    eax, ebx, ecx, edx, esp, ss, ebp, esi, edi,
    eip, eflags, cs, ds, es, fs, gs>;

}

#endif //XENDBG_REGISTERS_X86_HPP
