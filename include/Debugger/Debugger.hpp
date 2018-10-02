//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <memory>
#include <stdexcept>
#include <sys/mman.h>
#include <vector>

#include <capstone/capstone.h>
#include <spdlog/spdlog.h>
#include <uvw.hpp>

#include <Globals.hpp>
#include <Util/overloaded.hpp>
#include <Xen/Common.hpp>
#include <Xen/Domain.hpp>

namespace xd::dbg {

  class CapstoneException : public std::runtime_error {
  public:
    CapstoneException(const std::string &msg)
      : std::runtime_error(msg) {};
  };

  class NoSuchBreakpointException : public std::exception {
  public:
    explicit NoSuchBreakpointException(const xen::Address address)
        : _address(address) {};

    xen::Address get_address() const { return _address; };

  private:
    xen::Address _address;
  };

  class NoSuchSymbolException : public std::runtime_error {
  public:
    explicit NoSuchSymbolException(const std::string &name)
        : std::runtime_error(name) {};
  };

  using MaskedMemory = std::unique_ptr<unsigned char>;

  class Debugger {
  public:
    using OnBreakpointHitFn = std::function<void(xen::Address)>;

    Debugger(xen::Domain &domain);
    virtual ~Debugger();

    size_t get_vcpu_id() { return _vcpu_id; }

    void attach();
    void detach();

    virtual void continue_() = 0;
    virtual xen::Address single_step() = 0;

    virtual void cleanup() = 0;

    virtual void insert_breakpoint(xen::Address address) = 0;
    virtual void remove_breakpoint(xen::Address address) = 0;
    virtual std::optional<xen::Address> check_breakpoint_hit() = 0;
    virtual void on_breakpoint_hit(OnBreakpointHitFn on_breakpoint_hit) = 0;

    virtual MaskedMemory read_memory_masking_breakpoints(
        xen::Address address, size_t length) = 0;
    virtual void write_memory_retaining_breakpoints(
        xen::Address address, size_t length, void *data) = 0;

  protected:
    xen::Domain &_domain;

    std::pair<xen::Address, std::optional<xen::Address>> 
      get_address_of_next_instruction();

  private:
    csh _capstone;
    xen::VCPU_ID _vcpu_id;
  };

  template <typename Breakpoint_t, Breakpoint_t BREAKPOINT_VALUE>
  class DebuggerWithBreakpoints : public Debugger,
    public std::enable_shared_from_this<DebuggerWithBreakpoints<
                                  Breakpoint_t, BREAKPOINT_VALUE>>
  {
  private:
    static const Breakpoint_t _BREAKPOINT_VALUE = BREAKPOINT_VALUE;
    using BreakpointMap = std::unordered_map<xen::Address, Breakpoint_t>;

  public:
    DebuggerWithBreakpoints(xen::Domain &domain)
      : Debugger(domain) {};
    ~DebuggerWithBreakpoints() = default;

    void cleanup() override {
      for (const auto &bp : _breakpoints)
        remove_breakpoint(bp.first);
    }

    void continue_() override {
      // Single step first to move beyond the current breakpoint;
      // it will be removed during the step and replaced automatically.
      if (check_breakpoint_hit())
        single_step();

      _domain.unpause();
    }

    xen::Address single_step() override {
      _domain.pause();

      // If there's already a breakpoint here, remove it temporarily so we can continue
      std::optional<xen::Address> orig_addr;
      if ((orig_addr = check_breakpoint_hit()))
        remove_breakpoint(*orig_addr);

      // For conditional branches, we need to insert EBFEs at both potential locations.
      const auto [dest1_addr, dest2_addr_opt] = get_address_of_next_instruction();
      bool dest1_had_il = (_breakpoints.count(dest1_addr) != 0);
      bool dest2_had_il = dest2_addr_opt && (_breakpoints.count(*dest2_addr_opt) != 0);

      insert_breakpoint(dest1_addr);
      if (dest2_addr_opt && !dest2_had_il)
        insert_breakpoint(*dest2_addr_opt);

      _domain.unpause();
      std::optional<xen::Address> address_opt;
      while (!(address_opt = check_breakpoint_hit()));
      _domain.pause();

      // Remove each of our two infinite loops unless there is a
      // *manually-inserted* breakpoint at the corresponding address.
      if (!dest1_had_il)
        remove_breakpoint(dest1_addr);
      if (dest2_addr_opt && !dest2_had_il)
        remove_breakpoint(*dest2_addr_opt);

      // If there was a BP at the instruction we started at, put it back
      if (orig_addr)
        insert_breakpoint(*orig_addr);

      return *address_opt;
    }

    void insert_breakpoint(xen::Address address) override {
      spdlog::get(LOGNAME_CONSOLE)->debug("Inserting breakpoint at {0:x}", address);

      if (_breakpoints.count(address)) {
        spdlog::get(LOGNAME_ERROR)->info(
            "[!]: Tried to insert breakpoint where one already exists. "
            "This is generally harmless, but might indicate a failure in estimating the "
            "next instruction address.",
            address);
        return;
      }

      const auto mem_handle = _domain.map_memory<Breakpoint_t>(
          address, sizeof(Breakpoint_t), PROT_READ | PROT_WRITE);
      const auto mem = mem_handle.get();

      const auto orig_bytes = *mem;

      _breakpoints[address] = orig_bytes;
      *mem = _BREAKPOINT_VALUE;
    }

    std::optional<xen::Address> check_breakpoint_hit() override {
      const auto address = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(
          _domain.get_cpu_context());
      const auto mem_handle = _domain.map_memory<Breakpoint_t>(
          address, sizeof(Breakpoint_t), PROT_READ);
      const auto mem = mem_handle.get();

      if (*mem == _BREAKPOINT_VALUE && _breakpoints.count(address))
        return address;
      return std::nullopt;
    }

    void remove_breakpoint(xen::Address address) override {
      spdlog::get(LOGNAME_CONSOLE)->debug("Removing breakpoint at {0:x}", address);

      if (!_breakpoints.count(address)) {
        spdlog::get(LOGNAME_ERROR)->info(
            "[!]: Tried to remove infinite loop where one does not exist. "
            "This is generally harmless, but might indicate a failure in estimating the "
            "next instruction address.",
            address);
        return;
      }

      const auto mem_handle = _domain.map_memory<Breakpoint_t>(
          address, sizeof(Breakpoint_t), PROT_WRITE);
      const auto mem = (Breakpoint_t*)mem_handle.get();

      const auto orig_bytes = _breakpoints.at(address);
      *mem = orig_bytes;

      _breakpoints.erase(_breakpoints.find(address));
    }

    MaskedMemory read_memory_masking_breakpoints(
        xen::Address address, size_t length) override
    {
        const auto mem_handle = _domain.map_memory<char>(
            address, length, PROT_READ);

        const auto mem_masked = (unsigned char*)malloc(length);
        memcpy(mem_masked, mem_handle.get(), length);

        const auto address_end = address + length;
        for (const auto [bp_address, bp_orig_bytes] : _breakpoints) {
          if (bp_address >= address && bp_address < address_end) {
            const auto dist = bp_address - address;
            *((uint16_t*)(mem_masked + dist)) = bp_orig_bytes;
          }
      }

      return MaskedMemory(mem_masked);
    }

    void write_memory_retaining_breakpoints(
        xen::Address address, size_t length, void *data) override
    {
      const auto half_overlap_start_address = address-1;
      const auto half_overlap_end_address = address+length-1;

      const auto length_orig = length;
      if (_breakpoints.count(half_overlap_start_address)) {
        address -= 1;
        length += 1;
      }
      if (_breakpoints.count(half_overlap_end_address))
        length += 1;

      std::vector<xen::Address> bp_addresses;
      const auto address_end = address + length_orig;
      for (const auto [bp_address, _] : _breakpoints) {
        if (bp_address >= address && bp_address < address_end) {
          remove_breakpoint(bp_address);
          bp_addresses.push_back(bp_address);
        }
      }

      const auto mem_handle = _domain.map_memory<char>(address, length, PROT_WRITE);
      const auto mem_orig = (char*)mem_handle.get() + (length - length_orig);
      memcpy((void*)mem_orig, data, length_orig);

      spdlog::get(LOGNAME_ERROR)->info("Wrote {0:d} bytes to {1:x}.", length_orig, address);

      for (const auto &bp_address : bp_addresses)
        insert_breakpoint(bp_address);
    }

  protected:
    BreakpointMap _breakpoints;
  };

}


#endif //XENDBG_DEBUGGER_HPP
