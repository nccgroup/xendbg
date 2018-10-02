#include <GDBServer/GDBRequestHandler.hpp>

using xd::gdb::GDBRequestHandler;

template <>
void GDBRequestHandler::operator()(
    const req::InterruptRequest &) const
{
  _domain.pause();
  broadcast(rsp::StopReasonSignalResponse(SIGSTOP, 1));
}

template <>
void GDBRequestHandler::operator()(
    const req::StartNoAckModeRequest &) const
{
  _connection.disable_ack_mode();
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::QuerySupportedRequest &) const
{
  send(rsp::QuerySupportedResponse({
    "PacketSize=20000",
    "QStartNoAckMode+",
    "QThreadSuffixSupported+",
    "QListThreadsInStopReplySupported+",
  }));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryEnableErrorStrings &) const
{
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryThreadSuffixSupportedRequest &) const
{
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryListThreadsInStopReplySupportedRequest &) const
{
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryHostInfoRequest &) const
{
    send(rsp::QueryHostInfoResponse(
          _domain.get_word_size(), _domain.get_name()));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryRegisterInfoRequest &req) const
{
  const auto id = req.get_register_id();
  const auto word_size = _domain.get_word_size();

  if (word_size == sizeof(uint64_t)) {
    reg::x86_64::RegistersX86_64::find_metadata_by_id(id,
      [&](const auto &md) {
        send(rsp::QueryRegisterInfoResponse(
            md.name, 8*md.width, md.offset, md.gcc_id));
      }, [&]() {
        send_error(0x45);
      });
  } else if (word_size == sizeof(uint32_t)) {
    reg::x86_32::RegistersX86_32::find_metadata_by_id(id,
      [&](const auto &md) {
        send(rsp::QueryRegisterInfoResponse(
            md.name, 8*md.width, md.offset, md.gcc_id));
      }, [&]() {
        send_error(0x45);
      });
  } else {
    throw WordSizeException(word_size);
  }
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryProcessInfoRequest &) const
{
  send(rsp::QueryProcessInfoResponse(1));
}

// TODO: impl is PV-specific for now
template <>
void GDBRequestHandler::operator()(
    const req::QueryMemoryRegionInfoRequest &req) const
{
  const auto address = req.get_address();

  auto pte = _domain.get_page_table_entry(address);
  if (pte && pte->is_present()) {

    send(rsp::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, XC_PAGE_SIZE,
          true, pte->is_rw(), !pte->is_nx()));

  } else {

    /* If the current region (page) isn't present, LLDB expects that we
     * provide a region that represents the space before the next
     * one that IS present.
     */

    const auto MAX_ADDRESS = _domain.get_max_gpfn() << XC_PAGE_SHIFT;
    auto address_end = address;
    do {
      address_end += XC_PAGE_SIZE;
      pte = _domain.get_page_table_entry(address_end);
    } while (address_end < MAX_ADDRESS && !pte && !pte->is_present());

    send(rsp::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, address_end - address,
          false, false, false));
  }
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryCurrentThreadIDRequest &) const
{
  send(rsp::QueryCurrentThreadIDResponse(1));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryThreadInfoStartRequest &) const
{
  send(rsp::QueryThreadInfoResponse({1}));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryThreadInfoContinuingRequest &) const
{
  send(rsp::QueryThreadInfoEndResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::StopReasonRequest &) const
{
  send(rsp::StopReasonSignalResponse(SIGTRAP, 1));
}

template <>
void GDBRequestHandler::operator()(
    const req::KillRequest&) const
{
  _domain.destroy();
  broadcast(rsp::TerminatedResponse(SIGKILL));
}

template <>
void GDBRequestHandler::operator()(
    const req::SetThreadRequest&) const
{
  // TODO
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::RegisterReadRequest &req) const
{
  const auto id = req.get_register_id();
  const auto thread_id = req.get_thread_id();
  const auto regs = _domain.get_cpu_context(thread_id-1);

  std::visit(util::overloaded {
      [&](const auto &regs) {
        regs.find_by_id(id, [&](const auto&, const auto &reg) {
          send(rsp::RegisterReadResponse(reg));
        }, [&]() {
          send_error(0x45, "No register with ID " + std::to_string(id));
        });
      }
  }, regs);
}

template <>
void GDBRequestHandler::operator()(
    const req::RegisterWriteRequest &req) const
{
  const auto id = req.get_register_id();
  const auto value = req.get_value();

  auto regs = _domain.get_cpu_context();
  std::visit(util::overloaded {
      [&](auto &regs) {
        regs.find_by_id(id, [&value](const auto&, auto &reg) {
          reg = value;
        }, [&]() {
          send_error(0x45, "No register with ID " + std::to_string(id));
        });
      }
  }, regs);
  _domain.set_cpu_context(regs);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::GeneralRegistersBatchReadRequest &) const
{
  std::visit(util::overloaded {
      [&](const auto &regs) {
        send(rsp::GeneralRegistersBatchReadResponse(regs));
      }
  }, _domain.get_cpu_context());
}

template <>
void GDBRequestHandler::operator()(
    const req::GeneralRegistersBatchWriteRequest &req) const
{
  auto regs_any = _domain.get_cpu_context();
  auto values = req.get_values();

  std::visit(util::overloaded {
      [&values](auto &orig_regs) {
        size_t size = 0;
        while (!values.empty()) {
          const auto pair = values.back();
          values.pop_back();

          // For some reason, if I do [id, value] = values.back(),
          // 'value' isn't available for the lambda capture below
          const auto id = pair.first;
          const auto value = pair.second;

          orig_regs.find_by_id(id, [&](const auto &md, auto &reg) {
            std::visit(util::overloaded {
                [&](const auto &value) {
                  reg = value;
                  size = md.offset + md.width;
                }
            }, value);
          }, [&]() {
            throw PacketSizeException(size, orig_regs.size);
          });
        }
      }
  }, regs_any);

  _domain.set_cpu_context(regs_any);

  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::MemoryReadRequest &req) const
{
  const auto address = req.get_address();
  const auto length = req.get_length();

  const auto data = _debugger.read_memory_masking_breakpoints(address, length);
  send(rsp::MemoryReadResponse(data.get(), length));
}

template <>
void GDBRequestHandler::operator()(
    const req::MemoryWriteRequest &req) const
{
  const auto address = req.get_address();
  const auto length = req.get_length();
  const auto data = req.get_data();

  _debugger.write_memory_retaining_breakpoints(
      address, length, (void*)&data[0]);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::ContinueRequest &) const
{
  _debugger.on_breakpoint_hit([&](auto /*address*/) {
    _domain.pause();
    send(rsp::StopReasonSignalResponse(SIGTRAP, 1)); // TODO
  });

  _debugger.continue_();

  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::StepRequest &) const
{
  _debugger.single_step();
  broadcast(rsp::StopReasonSignalResponse(SIGTRAP, 1));
}

template <>
void GDBRequestHandler::operator()(
    const req::BreakpointInsertRequest &req) const
{
  const auto address = req.get_address();
  _debugger.insert_breakpoint(address);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::BreakpointRemoveRequest &req) const
{
  const auto address = req.get_address();
  _debugger.remove_breakpoint(address);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::RestartRequest &) const
{
  send(rsp::NotSupportedResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::DetachRequest &) const
{
  _debugger.detach();
  _connection.stop();
  send(rsp::OKResponse());
}
