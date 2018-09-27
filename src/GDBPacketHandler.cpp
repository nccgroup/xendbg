#include "GDBPacketHandler.hpp"

using namespace xd::gdbsrv::pkt;
using xd::GDBPacketHandler;

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::InterruptRequest &) const
{
  _domain.pause();
  broadcast(gdbsrv::pkt::StopReasonSignalResponse(SIGSTOP, 1));
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::StartNoAckModeRequest &) const
{
  _connection.disable_ack_mode();
  send(gdbsrv::pkt::OKResponse());
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QuerySupportedRequest &) const
{
  send(gdbsrv::pkt::QuerySupportedResponse({
    "PacketSize=20000",
    "QStartNoAckMode+",
    "QThreadSuffixSupported+",
    "QListThreadsInStopReplySupported+",
  }));
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryThreadSuffixSupportedRequest &) const
{
  send(gdbsrv::pkt::OKResponse());
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryListThreadsInStopReplySupportedRequest &) const
{
  send(gdbsrv::pkt::OKResponse());
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryHostInfoRequest &) const
{
    send(gdbsrv::pkt::QueryHostInfoResponse(
          _domain.get_word_size(), _domain.get_name()));
};

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryRegisterInfoRequest &req) const
{
  const auto id = req.get_register_id();
  const auto word_size = _domain.get_word_size();

  if (word_size == sizeof(uint64_t)) {
    reg::x86_64::RegistersX86_64::find_metadata_by_id(id,
      [&](const auto &md) {
        send(gdbsrv::pkt::QueryRegisterInfoResponse(
            md.name, 8*md.width, md.offset, md.gcc_id));
      }, [&]() {
        send(gdbsrv::pkt::ErrorResponse(0x45));
      });
  } else if (word_size == sizeof(uint32_t)) {
    reg::x86_32::RegistersX86_32::find_metadata_by_id(id,
      [&](const auto &md) {
        send(gdbsrv::pkt::QueryRegisterInfoResponse(
            md.name, 8*md.width, md.offset, md.gcc_id));
      }, [&]() {
        send(gdbsrv::pkt::ErrorResponse(0x45));
      });
  } else {
    throw std::runtime_error("Unsupported word size!");
  }
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryProcessInfoRequest &) const
{
  send(gdbsrv::pkt::QueryProcessInfoResponse(1));
}

// TODO: impl is PV-specific for now
template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryMemoryRegionInfoRequest &req) const
{
  const auto address = req.get_address();

  auto pte = _domain.get_page_table_entry(address);
  auto length = XC_PAGE_SIZE;

  if (pte.is_present() ) {

    send(gdbsrv::pkt::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, length,
          true, pte.is_rw(), !pte.is_nx()));

  } else {

    /* If the current region (page) isn't present, LLDB expects that we
     * provide a region that represents the space before the next
     * one that IS present.
     */
    auto address2 = address;
    do {
      address2 += XC_PAGE_SIZE;
      pte = _domain.get_page_table_entry(address2);
    } while (!pte.is_present());

    length = address2 - address;
    send(gdbsrv::pkt::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, length,
          false, false, false));
  }
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryCurrentThreadIDRequest &) const
{
  send(gdbsrv::pkt::QueryCurrentThreadIDResponse(1));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryThreadInfoStartRequest &) const
{
  send(gdbsrv::pkt::QueryThreadInfoResponse({1}));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::QueryThreadInfoContinuingRequest &) const
{
  send(gdbsrv::pkt::QueryThreadInfoEndResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::StopReasonRequest &) const
{
  send(gdbsrv::pkt::StopReasonSignalResponse(SIGTRAP, 1));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::KillRequest&) const
{
  _domain.destroy();
  broadcast(gdbsrv::pkt::TerminatedResponse(SIGKILL));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::SetThreadRequest&) const
{
  // TODO
  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::RegisterReadRequest &req) const
{
  const auto id = req.get_register_id();
  const auto thread_id = req.get_thread_id();
  const auto regs = _domain.get_cpu_context(thread_id-1);

  std::visit(util::overloaded {
      [&](const auto &regs) {
        regs.find_by_id(id, [&](const auto&, const auto &reg) {
          send(gdbsrv::pkt::RegisterReadResponse(reg));
        }, [&]() {
          send(gdbsrv::pkt::ErrorResponse(0x45)); // TODO
        });
      }
  }, regs);
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::RegisterWriteRequest &req) const
{
  const auto id = req.get_register_id();
  const auto value = req.get_value();

  auto regs = _domain.get_cpu_context();
  std::visit(util::overloaded {
      [&](auto &regs) {
        regs.find_by_id(id, [&value](const auto&, auto &reg) {
          reg = value;
        }, [&]() {
          send(gdbsrv::pkt::ErrorResponse(0x45)); // TODO
        });
      }
  }, regs);
  _domain.set_cpu_context(regs);
  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::GeneralRegistersBatchReadRequest &) const
{
  std::visit(util::overloaded {
      [&](const auto &regs) {
        send(gdbsrv::pkt::GeneralRegistersBatchReadResponse(regs));
      }
  }, _domain.get_cpu_context());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::GeneralRegistersBatchWriteRequest &req) const
{
  auto regs_any = _domain.get_cpu_context();
  auto values = req.get_values();

  std::visit(util::overloaded {
      [&values](auto &orig_regs) {
        const auto pair = values.back();
        values.pop_back();

        // For some reason, if I do [id, value] = values.back(),
        // 'value' isn't available for the lambda capture below
        const auto id = pair.first;
        const auto value = pair.second;

        orig_regs.find_by_id(id, [value](const auto&, auto &reg) {
          std::visit(util::overloaded {
              [&reg](const auto &value) {
                reg = value;
              }
          }, value);
        }, [&]() {
          throw std::runtime_error("Oversized register write packet!");
        });
      }
  }, regs_any);

  _domain.set_cpu_context(regs_any);

  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::MemoryReadRequest &req) const
{
  const auto address = req.get_address();
  const auto length = req.get_length();

  const auto data = _debugger.read_memory_masking_breakpoints(address, length);
  send(gdbsrv::pkt::MemoryReadResponse(data.get(), length));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::MemoryWriteRequest &req) const
{
  const auto address = req.get_address();
  const auto length = req.get_length();
  const auto data = req.get_data();

  _debugger.write_memory_retaining_breakpoints(
      address, length, (void*)&data[0]);
  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::ContinueRequest &) const
{
  _debugger.continue_();

  _debugger.notify_breakpoint_hit([&](auto /*address*/) {
    _domain.pause();
    send(gdbsrv::pkt::StopReasonSignalResponse(SIGTRAP, 1)); // TODO
  });

  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::StepRequest &) const
{
  _debugger.single_step();
  broadcast(gdbsrv::pkt::StopReasonSignalResponse(SIGTRAP, 1));
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::BreakpointInsertRequest &req) const
{
  const auto address = req.get_address();
  _debugger.insert_breakpoint(address);
  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::BreakpointRemoveRequest &req) const
{
  const auto address = req.get_address();
  _debugger.remove_breakpoint(address);
  send(gdbsrv::pkt::OKResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::RestartRequest &) const
{
  send(gdbsrv::pkt::NotSupportedResponse());
}

template <>
void GDBPacketHandler::operator()(
    const gdbsrv::pkt::DetachRequest &) const
{
  _debugger.detach();
  _connection.stop();
  send(gdbsrv::pkt::OKResponse());
}
