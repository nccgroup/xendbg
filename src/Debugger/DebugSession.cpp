//
// Created by Spencer Michaels on 9/20/18.
//

#define X86_MAX_INSTRUCTION_SIZE 0x10

#include "DebugSession.hpp"

using xd::dbg::DebugSession;
using xd::xen::Address ;
using xd::xen::DomID;

DebugSession::DebugSession(const xen::XenHandle& xen, xen::DomID domid)
  : _xen(xen), _domain(xen, domid), _vcpu_id(0)
{
  _domain.pause();
  _domain.set_debugging(true);

  const auto mode =
      (_domain.get_word_size() == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

  if (cs_open(CS_ARCH_X86, mode, &_capstone) != CS_ERR_OK)
    throw std::runtime_error("Failed to open Capstone handle!");

  cs_option(_capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

DebugSession::~DebugSession() {
  _domain.unpause();
  cs_close(&_capstone);
}

std::optional<Address> DebugSession::check_breakpoint_hit() {
  return std::optional<Address>();
}

std::pair<std::optional<Address>, std::optional<Address>>
DebugSession::get_address_of_next_instruction() {
  const auto read_word = [this](Address addr) {
    const auto mem_handle = _domain.map_memory(addr, sizeof(uint64_t), PROT_READ);
    if (_domain.get_word_size() == sizeof(uint64_t)) {
      return *((uint64_t*)mem_handle.get());
    } else {
      return (uint64_t)(*((uint32_t*)mem_handle.get()));
    }
  };
  const auto read_reg_cs = [this](auto cs_reg)
  {
    const auto reg_name = cs_reg_name(_capstone, cs_reg);
    assert(reg_name != nullptr);
    // TODO:regs --- should implement register context iterator for this
    return 0;
    //return _domain->read_register(std::string(reg_name));
  };

  const auto address = read_register<reg::x86_32::eip, reg::x86_64::rip>();

  const auto read_size = (2*X86_MAX_INSTRUCTION_SIZE);
  const auto mem_handle = _domain.map_memory(address, read_size, PROT_READ);
  const auto mem = (uint8_t*)mem_handle.get();

  cs_insn *instrs;
	size_t instrs_size;

  instrs_size = cs_disasm(_capstone, mem, read_size-1, address, 0, &instrs);

  if (instrs_size < 2)
    throw std::runtime_error("Failed to read instructions!");

  auto cur_instr = instrs[0];
  const auto next_instr_address = instrs[1].address;

  // JMP and CALL
  if (cs_insn_group(_capstone, &cur_instr, X86_GRP_JUMP) ||
      cs_insn_group(_capstone, &cur_instr, X86_GRP_CALL))
  {
    const auto x86 = cur_instr.detail->x86;
    assert(x86.op_count != 0);
    const auto op = x86.operands[0];

    if (op.type == X86_OP_IMM) {
      const auto dest = op.imm;
      return std::make_pair(next_instr_address, dest);
    } else if (op.type == X86_OP_MEM) {
      /*
      const auto base = op.mem.base ? read_reg_cs(op.mem.base) : 0;
      const auto index = op.mem.index ? read_reg_cs(op.mem.base) : 0;
      const auto dest = base + (op.mem.scale * index); // TODO: is this right?
      std::cout << "mem disp: " << op.mem.disp << std::endl;
      */
      throw std::runtime_error("JMP/CALL(MEM) not supported!");
    } else if (op.type == X86_OP_REG) {
      const auto reg_value = read_reg_cs(op.reg);
      return std::make_pair(std::nullopt, reg_value);
    } else {
      throw std::runtime_error("JMP/CALL operand type not supported?");
    }
  }

  // RET
  else if (cs_insn_group(_capstone, &cur_instr, X86_GRP_RET) ||
             cs_insn_group(_capstone, &cur_instr, X86_GRP_IRET))
  {
    const auto stack_ptr = read_register<reg::x86_32::esp, reg::x86_64::rsp>();
    const auto ret_dest = read_word(stack_ptr);
    return std::make_pair(std::nullopt, ret_dest);
  }

  // Any other instructions
  else {
    return std::make_pair(next_instr_address, std::nullopt);
  }
}
