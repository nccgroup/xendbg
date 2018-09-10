
//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_X86_HPP
#define XENDBG_REGISTERS_X86_HPP

#include "Register.hpp"
#include "RegisterContext.hpp"

namespace reg::x86 {

  DECLARE_REGISTER(eax,    uint32_t);
  DECLARE_REGISTER(ebx,    uint32_t);
  DECLARE_REGISTER(ecx,    uint32_t);
  DECLARE_REGISTER(edx,    uint32_t);
  DECLARE_REGISTER(edi,    uint32_t);
  DECLARE_REGISTER(esi,    uint32_t);
  DECLARE_REGISTER(ebp,    uint32_t);
  DECLARE_REGISTER(esp,    uint32_t);
  DECLARE_REGISTER(ss,     uint32_t);
  DECLARE_REGISTER(eip,    uint32_t);
  DECLARE_REGISTER(eflags, uint16_t);
  DECLARE_REGISTER(cs,     uint16_t);
  DECLARE_REGISTER(ds,     uint16_t);
  DECLARE_REGISTER(es,     uint16_t);
  DECLARE_REGISTER(fs,     uint16_t);
  DECLARE_REGISTER(gs,     uint16_t);

  using RegistersX86 = RegisterContext<
    eax, ebx, ecx, edx, esp, ebp, esi, edi,
    eflags, eip, fs, gs, cs, ds, ss>; 

}

#endif //XENDBG_REGISTERS_X86_HPP
