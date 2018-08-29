//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_REGISTERS_HPP
#define XENDBG_REGISTERS_HPP

#include "BridgeHeaders/xenctrl.h"

#include <cstdint>
#include <string>
#include <variant>

namespace xd::xen {

  struct Registers32 {
    using ValueType = uint32_t;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ss;
    uint16_t eflags;
    uint32_t eip;
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;

    ValueType get_by_name(const std::string &name) const;
    void set_by_name(const std::string &name, ValueType value);

    template <typename F>
    void for_each(F f) const {
      static constexpr auto names = {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "edi",
        "esi",
        "ebp",
        "esp",
        "ss",
        "eflags",
        "eip",
        "cs",
        "ds",
        "es",
        "fs",
        "gs"
      };

      for (const auto &name : names) {
        f(name, get_by_name(name));
      }
    };
  };

  struct Registers64 {
    using ValueType = uint64_t;

    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
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
    uint16_t rflags;
    uint64_t rip;
    uint64_t fs;
    uint64_t gs;
    uint64_t cs;
    uint64_t ds;
    uint64_t ss;

    ValueType get_by_name(const std::string &name) const;
    void set_by_name(const std::string &name, ValueType value);

    template <typename F>
    void for_each(F f) const {
      static constexpr auto names = {
          "rax",
          "rbx",
          "rcx",
          "rdx",
          "rsp",
          "rbp",
          "rsi",
          "rdi",
          "r8",
          "r9",
          "r10",
          "r11",
          "r12",
          "r13",
          "r14",
          "r15",
          "rflags",
          "rip",
          "fs",
          "gs",
          "cs",
          "ds",
          "ss"
      };

      for (const auto &name : names) {
        f(name, get_by_name(name));
      }
    };
  };

  using Registers = std::variant<Registers32, Registers64>;

  template <typename Source_t, typename Result_t>
  Result_t convert_gp_registers_32(const Source_t& source, Result_t regs_init) {
    regs_init.eax = source.eax;
    regs_init.ebx = source.ebx;
    regs_init.ecx = source.ecx;
    regs_init.edx = source.edx;
    regs_init.edi = source.edi;
    regs_init.esi = source.esi;
    regs_init.ebp = source.ebp;
    regs_init.esp = source.esp;
    regs_init.ss = source.ss;
    regs_init.eflags = source.eflags;
    regs_init.eip = source.eip;
    regs_init.cs = source.cs;
    regs_init.ds = source.ds;
    regs_init.es = source.es;
    regs_init.fs = source.fs;
    regs_init.gs = source.gs;

    return regs_init;
  }

  /*
   * This is all needed because registers like fs, gs, etc. aren't
   * named consistently between the PV and HVM register data structures.
   */
  template <typename Source_t, typename Result_t>
  Result_t _convert_gp_registers_any64_partial(const Source_t &source, Result_t regs_init) {
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

    return regs_init;
  }

  template <typename Source_t, typename Result_t>
  struct _convert_gp_registers_64_impl {
    static Result_t convert(const Source_t &source, Result_t regs_init) {
      auto regs = _convert_gp_registers_any64_partial(source, regs_init);
      regs.fs = source.fs;
      regs.gs = source.gs;
      regs.cs = source.cs;
      regs.ds = source.ds;
      regs.ss = source.ss;
      return regs;
    }
  };

  template <>
  struct _convert_gp_registers_64_impl<struct hvm_hw_cpu, Registers64> {
    static Registers64 convert(const struct hvm_hw_cpu& source, Registers64 regs_init) {
      auto regs = _convert_gp_registers_any64_partial(source, regs_init);
      regs.fs = source.fs_base;
      regs.gs = source.gs_base;
      regs.cs = source.cs_base;
      regs.ds = source.ds_base;
      regs.ss = source.ss_base;
      return regs;
    }
  };

  template <>
  struct _convert_gp_registers_64_impl<Registers64, struct hvm_hw_cpu> {
    static struct hvm_hw_cpu convert(const Registers64& source, struct hvm_hw_cpu regs_init) {
      auto regs = _convert_gp_registers_any64_partial(source, regs_init);
      regs.fs_base = source.fs;
      regs.gs_base = source.gs;
      regs.cs_base = source.cs;
      regs.ds_base = source.ds;
      regs.ss_base = source.ss;
      return regs;
    }
  };

  template <typename Source_t, typename Result_t>
  Result_t convert_gp_registers_64(const Source_t &source, Result_t regs_init) {
    return _convert_gp_registers_64_impl<Source_t, Result_t>::convert(source, regs_init);
  }

}

#endif //XENDBG_REGISTERS_HPP
