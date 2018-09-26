//
// Created by Spencer Michaels on 9/20/18.
//

#define X86_MAX_INSTRUCTION_SIZE 0x10

#include <Debugger/DebugSession.hpp>

using xd::dbg::DebugSession;
using xd::uv::UVLoop;
using xd::xen::Address;
using xd::xen::DomID;

DebugSession::DebugSession(UVLoop &loop, xen::Domain domain)
  : _domain(std::move(domain)), _timer(loop), _vcpu_id(0)
{
  _timer.data = this; // TODO

  const auto mode =
      (_domain.get_word_size() == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

  if (cs_open(CS_ARCH_X86, mode, &_capstone) != CS_ERR_OK)
    throw std::runtime_error("Failed to open Capstone handle!");

  cs_option(_capstone, CS_OPT_DETAIL, CS_OPT_ON);
}

DebugSession::~DebugSession() {
  cs_close(&_capstone);
}

void DebugSession::attach() {
  _domain.set_debugging(true);
  _domain.pause();
}

void DebugSession::detach() {
  for (const auto address : get_breakpoints())
    remove_breakpoint(address);
  _domain.unpause();
}

void DebugSession::notify_breakpoint_hit(OnBreakpointHitFn on_breakpoint_hit) {
  _timer.start([on_breakpoint_hit](auto &timer) {
    auto self = (DebugSession*) timer.data;
    auto address = self->check_breakpoint_hit();
    if (address) {
      timer.stop();
      on_breakpoint_hit(*address);
    }
    return address.has_value();
  }, 100, 100);
}

std::pair<std::optional<Address>, std::optional<Address>>
DebugSession::get_address_of_next_instruction() {
  const auto read_word = [this](Address addr) {
    const auto mem_handle = _domain.map_memory<uint64_t>(addr, sizeof(uint64_t), PROT_READ);
    if (_domain.get_word_size() == sizeof(uint64_t)) {
      return *mem_handle;
    } else {
      return (uint64_t)(*((uint32_t*)mem_handle.get()));
    }
  };

  // TODO: need functionality to get register by name
  const auto read_regs_from_cs_reg = [this](const auto &regs, auto cs_reg)
  {
    const auto reg_name = cs_reg_name(_capstone, cs_reg);
    return 0;
  };

  const auto address = read_register<reg::x86_32::eip, reg::x86_64::rip>();

  const auto read_size = (2*X86_MAX_INSTRUCTION_SIZE);
  const auto mem_handle = _domain.map_memory<uint8_t>(address, read_size, PROT_READ);

  cs_insn *instrs;
	size_t instrs_size;

  instrs_size = cs_disasm(_capstone, mem_handle.get(), read_size-1, address, 0, &instrs);

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
      throw std::runtime_error("JMP/CALL(MEM) not supported!"); // TODO
    } else if (op.type == X86_OP_REG) {
      //const auto reg_value = read_regs_from_cs_reg(op.reg);
      //return std::make_pair(std::nullopt, reg_value);
      throw std::runtime_error("JMP/CALL(REG) not supported!"); // TODO
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
