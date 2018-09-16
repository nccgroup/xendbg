//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include <capstone/capstone.h>

#include "Debugger.hpp"
#include "../Util/overloaded.hpp"

#define X86_MAX_INSTRUCTION_SIZE 0x10
#define X86_INFINITE_LOOP 0xFEEB

using xd::dbg::Debugger;
using xd::dbg::NoSuchSymbolException;
using xd::dbg::NoSuchVariableException;
using xd::xen::Address;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Domain& Debugger::attach(DomID domid) {
  _current_vcpu = 0;
  _domain.emplace(_xen, domid);
  _domain->pause();
  _domain->set_debugging(true);

  const auto mode =
    (_domain->get_word_size() == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

  if (cs_open(CS_ARCH_X86, mode, &_capstone) != CS_ERR_OK)
    throw std::runtime_error("Failed to open Capstone handle!");

  cs_option(_capstone, CS_OPT_DETAIL, CS_OPT_ON);

  return _domain.value();
}

void Debugger::detach() {
  for (const auto &il : _infinite_loops) {
    remove_infinite_loop(il.first);
  }

  cs_close(&_capstone);

  _domain.reset();
}

Address Debugger::continue_until_infinite_loop() {
  if (!_domain)
    throw NoGuestAttachedException();

  // Single step first to move beyond the current breakpoint;
  // it will be removed during the step and replaced automatically.
  if (check_infinite_loop_hit())
    single_step();

  _domain->unpause();

  std::optional<Address> address;
  while (!(address = check_infinite_loop_hit()) &&
         !_domain->get_info().paused); // TODO hack for now

  _domain->pause();

  return *address;
}

void Debugger::single_step() {
  if (!_domain)
    throw NoGuestAttachedException();

  _domain->pause();

  // If there's already a breakpoint here, remove it temporarily so we can continue
  std::optional<Address> orig_addr;
  if ((orig_addr = check_infinite_loop_hit()))
    remove_infinite_loop(*orig_addr);

  // For conditional branches, we need to insert EBFEs at both potential locations.
  const auto [dest1_addr, dest2_addr] = get_address_of_next_instruction();
  bool dest1_had_il = dest1_addr && !!_infinite_loops.count(*dest1_addr);
  bool dest2_had_il = dest2_addr && !!_infinite_loops.count(*dest2_addr);

  if (!dest1_had_il)
    insert_infinite_loop(*dest1_addr);
  if (!dest2_had_il)
    insert_infinite_loop(*dest2_addr);

  _domain->unpause();
  while (!(check_infinite_loop_hit()));
  _domain->pause();

  // Remove each of our two infinite loops unless there is a
  // *manually-inserted* breakpoint at the corresponding address.
  if (dest1_addr && !dest1_had_il)
    remove_infinite_loop(*dest1_addr);
  if (dest2_addr && !dest2_had_il)
    remove_infinite_loop(*dest2_addr);

  // If there was a BP at the instruction we started at, put it back
  if (orig_addr)
    insert_infinite_loop(*orig_addr);
}

std::vector<Domain> Debugger::get_guest_domains() {
  const auto domids = _xen.get_xenstore().get_guest_domids();

  std::vector<Domain> domains;
  domains.reserve(domids.size());
  std::transform(domids.begin(), domids.end(), std::back_inserter(domains),
    [this](const auto& domid) {
      return Domain(_xen, domid);
    });
  return domains;
}

std::optional<Address> Debugger::check_infinite_loop_hit() {
  const auto address = std::visit(util::overloaded {
    [](const reg::x86_32::RegistersX86_32 regs) {
      return (uint64_t)regs.get<reg::x86_32::eip>();
    },
    [](const reg::x86_64::RegistersX86_64 regs) {
      return (uint64_t)regs.get<reg::x86_64::rip>();
    }
  }, _domain->get_cpu_context(_current_vcpu));

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ);
  const auto mem = (uint16_t*)mem_handle.get();

  if (*mem == X86_INFINITE_LOOP && _infinite_loops.count(address))
    return address;
  return std::nullopt;
}

std::pair<std::optional<Address>, std::optional<Address>>
  Debugger::get_address_of_next_instruction()
{
  const auto read_word = [this](Address addr) {
    const auto mem_handle = _domain->map_memory(addr, sizeof(uint64_t), PROT_READ);
    if (_domain->get_word_size() == sizeof(uint64_t)) {
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
  const auto mem_handle = _domain->map_memory(address, read_size, PROT_READ);
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
    const auto ret_dest = read_word(read_esp_rsp());
    return std::make_pair(std::nullopt, ret_dest);
  }

  // Any other instructions
  else {
    return std::make_pair(next_instr_address, std::nullopt);
  }
}

void Debugger::insert_infinite_loop(xen::Address address) {
  if (!_domain)
    throw NoGuestAttachedException();
  if (_infinite_loops.count(address)) {
    std::cout << "[!]: Tried to insert infinite loop where one already exists." << std::endl;
    return; // TODO?
  }
  std::cout << "Inserting infinite loop." << std::endl;

  const auto mem_handle = _domain->map_memory(address, 2, PROT_READ | PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  const auto orig_bytes = *mem;

  _infinite_loops[address] = orig_bytes;
  *mem = X86_INFINITE_LOOP;
}

void Debugger::remove_infinite_loop(xen::Address address) {
  if (!_infinite_loops.count(address))
    throw NoSuchInfiniteLoopException(address);

  std::cout << "Removing infinite loop." << std::endl;

  const auto mem_handle = _domain->map_memory(address, 2, PROT_WRITE);
  const auto mem = (uint16_t*)mem_handle.get();

  const auto orig_bytes = _infinite_loops[address];
  *mem = orig_bytes;

  _infinite_loops.erase(_infinite_loops.find(address));
}

Debugger::MaskedMemory Debugger::read_memory_masking_infinite_loops(
    xen::Address address, size_t length)
{
  const auto mem_handle = get_current_domain()->map_memory(
      address, length, PROT_READ);

  const auto mem_masked = (unsigned char*)malloc(length);
  memcpy(mem_masked, mem_handle.get(), length);

  const auto address_end = address + length;
  for (const auto [il_address, il_orig_bytes] : _infinite_loops) {
    if (il_address >= address && il_address < address_end) {
      const auto dist = il_address - address;
      *((uint16_t*)(mem_masked + dist)) = il_orig_bytes;
    }
  }

  return MaskedMemory(mem_masked);
}

/* TODO: There is still an edge case where one or both ends of the mapped
 * region contain one --- but not both --- bytes of an infinite loop.
 * I think the best fix for this is to expand the range by 1 in both directions,
 * remove all ILs within the new range (thus replacing the original memory
 * values), write the new memory, and then re-insert the ILs (thus getting the
 * new orig_bytes values).
 */
void Debugger::write_memory_retaining_infinite_loops(
    xen::Address address, size_t length, void *data)
{
  const auto half_overlap_start_address = address-1;
  const auto half_overlap_end_address = address+length-1;

  const auto length_orig = length;
  if (_infinite_loops.count(half_overlap_start_address)) {
    address -= 1;
    length += 1;
  }
  if (_infinite_loops.count(half_overlap_end_address))
    length += 1;

  std::vector<Address> il_addresses;
  const auto address_end = address + length_orig;
  for (const auto [il_address, _] : _infinite_loops) {
    if (il_address >= address && il_address < address_end) {
      remove_infinite_loop(il_address);
      il_addresses.push_back(il_address);
    }
  }

  const auto mem_handle = _domain->map_memory(address, length, PROT_WRITE);
  const auto mem_orig = (char*)mem_handle.get() + (length - length_orig);
  memcpy((void*)mem_orig, data, length_orig);

  std::cout << std::hex << "wrote " << length_orig << " bytes to " << address << std::endl;

  for (const auto &il_address : il_addresses)
    insert_infinite_loop(il_address);
}
