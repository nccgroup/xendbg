//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//


#ifndef XENDBG_REGISTERS_X86_HPP
#define XENDBG_REGISTERS_X86_HPP

#include "Register.hpp"
#include "RegisterContext.hpp"
#include "RegistersX86.hpp"

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

  using RegistersX86_32 = RegisterContext<
    eax, ebx, ecx, edx, esp, ss, ebp, esi, edi,
    eip, eflags, cs, ds, es, fs, gs,
    x86::cr0, x86::cr3, x86::cr4, x86::msr_efer>;

}

#endif //XENDBG_REGISTERS_X86_HPP
