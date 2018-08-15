//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_REGISTERS_HPP
#define XENDBG_REGISTERS_HPP

#include <cstdint>
#include <variant>

namespace xd::xen {

  struct Registers32 {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ss;
    uint32_t eflags;
    uint32_t eip;
    uint32_t cs_base;
    uint32_t ds_base;
    uint32_t es_base;
    uint32_t fs_base;
    uint32_t gs_base;
  };

  struct Registers64 {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t cs_base;
  };

  using Registers = std::variant<Registers32, Registers64>;

  template <typename Source_t, typename Result_t>
  Result_t convert_gp_registers_32(Source_t source, Result_t regs_init) {
    regs_init.eax = source.eax;
    regs_init.ebx = source.ebx;
    regs_init.ecx = source.ecx;
    regs_init.edx = source.edx;
    regs_init.edi = source.edi;
    regs_init.esi = source.esi;
    regs_init.ebp = source.ebp;
    regs_init.esp = source.esp;
    regs_init.eflags = source.eflags;
    regs_init.eip = source.esip;
    regs_init.cs_base = source.cs_base;
    regs_init.ds_base = source.ds_base;
    regs_init.es_base = source.es_base;
    regs_init.fs_base = source.fs_base;
    regs_init.gs_base = source.gs_base;

    return regs_init;
  }

  template <typename Source_t, typename Result_t>
  Result_t convert_gp_registers_64(Source_t source, Result_t regs_init) {
    regs_init.rax = source.rax;
    regs_init.rbx = source.rbx;
    regs_init.rcx = source.rcx;
    regs_init.rdx = source.rdx;
    regs_init.rbp = source.rbp;
    regs_init.rsi = source.rsi;
    regs_init.rdi = source.rdi;
    regs_init.rsp = source.rsp;
    regs_init.r8 = source.r8;
    regs_init.r9 = source.r9;
    regs_init.r10 = source.r10;
    regs_init.r11 = source.r11;
    regs_init.r12 = source.r12;
    regs_init.r13 = source.r13;
    regs_init.r14 = source.r14;
    regs_init.r15 = source.r15;
    regs_init.rip = source.rip;
    regs_init.rflags = source.rflags;
    regs_init.fs_base = source.fs_base;
    regs_init.gs_base = source.gs_base;
    regs_init.cs_base = source.cs_base;

    return regs_init;
  }
}

#endif //XENDBG_REGISTERS_HPP
