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

#include <GDBServer/GDBRequestHandler.hpp>

using xd::gdb::GDBRequestHandler;

std::vector<size_t> GDBRequestHandler::get_thread_ids() const {
  const auto max_vcpu_id = _debugger.get_domain().get_dominfo().max_vcpu_id;
  std::vector<size_t> thread_ids;
  for (unsigned long vcpu_id = 0; vcpu_id <= max_vcpu_id; ++vcpu_id)
    thread_ids.push_back(vcpu_id+1);
  return thread_ids;
}

template <>
void GDBRequestHandler::operator()(
    const req::InterruptRequest &) const
{
  _debugger.get_domain().pause();
  send(rsp::StopReasonSignalResponse(SIGSTOP, 1, get_thread_ids()));
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
    const req::QueryWatchpointSupportInfo &) const
{
  send(rsp::QueryWatchpointSupportInfoResponse(std::numeric_limits<uint32_t>::max()));
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
          _debugger.get_domain().get_word_size(), _debugger.get_domain().get_name()));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryRegisterInfoRequest &req) const
{
  const auto id = req.get_register_id();
  const auto word_size = _debugger.get_domain().get_word_size();

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
  send(rsp::NotSupportedResponse());

  /*
  const auto address = req.get_address();

  auto perms = _debugger.get_domain().get_page_permissions(address);
  if (perms) {

    send(rsp::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, XC_PAGE_SIZE,
          perms->read, perms->write, perms->execute));

  } else {

    \* If the current region (page) isn't present, LLDB expects that we
     * provide a region that represents the space before the next
     * one that IS present.
     *\

    const auto MAX_ADDRESS = _debugger.get_domain().get_max_gpfn() << XC_PAGE_SHIFT;
    auto address_end = address;

    do {
      address_end += std::min(XC_PAGE_SIZE, MAX_ADDRESS - address);
      perms = _debugger.get_domain().get_page_permissions(address_end);
    } while (address_end < MAX_ADDRESS && !perms);

    send(rsp::QueryMemoryRegionInfoResponse(
          address & XC_PAGE_MASK, address_end - address,
          false, false, false));
  }
  */
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryCurrentThreadIDRequest &) const
{
  send(rsp::QueryCurrentThreadIDResponse(_debugger.get_vcpu_id()));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryThreadInfoStartRequest &) const
{
  send(rsp::QueryThreadInfoResponse(get_thread_ids()));
}

template <>
void GDBRequestHandler::operator()(
    const req::QueryThreadInfoContinuingRequest &) const
{
  send(rsp::QueryThreadInfoEndResponse());
}

void GDBRequestHandler::send_stop_reply(dbg::StopReason reason_any) const {
  std::visit(util::overloaded {
    [this](dbg::StopReasonBreakpoint reason) {
      send(rsp::StopReasonSignalResponse(reason.signal, reason.vcpu_id, get_thread_ids()));
    }, [this](dbg::StopReasonWatchpoint reason) {
      std::string type_str;
      switch (reason.type) {
        case dbg::WatchpointType::Access:
          type_str = "awatch";
        case dbg::WatchpointType::Read:
          type_str = "rwatch";
        case dbg::WatchpointType::Write:
          type_str = "watch";
      };

      std::stringstream ss;
      ss << std::hex << reason.address;

      send(rsp::StopReasonSignalResponse(reason.signal, reason.vcpu_id, get_thread_ids(),
            type_str, ss.str()));
    }
  }, reason_any);
}

template <>
void GDBRequestHandler::operator()(
    const req::StopReasonRequest &) const
{
  send_stop_reply(_debugger.get_last_stop_reason());
}

template <>
void GDBRequestHandler::operator()(
    const req::KillRequest&) const
{
  _debugger.get_domain().destroy();
  send(rsp::TerminatedResponse(SIGKILL));
}

template <>
void GDBRequestHandler::operator()(
    const req::SetThreadRequest &req) const
{
  // TODO: -1 means "all threads"... need to implement better support for this
  const auto thread_id = req.get_thread_id();
  if (thread_id != (size_t)-1 && thread_id != 0)
    _debugger.set_vcpu_id(thread_id);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::RegisterReadRequest &req) const
{
  const auto id = req.get_register_id();
  const auto thread_id = req.get_thread_id();
  const auto vcpu_id = (thread_id == (size_t)-1) ? 0 : thread_id-1;
  const auto regs = _debugger.get_domain().get_cpu_context(vcpu_id);

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
  const auto thread_id = req.get_thread_id();
  const auto vcpu_id = (thread_id == (size_t)-1) ? 0 : thread_id-1;

  auto regs = _debugger.get_domain().get_cpu_context(vcpu_id);
  std::visit(util::overloaded {
      [&](auto &regs) {
        regs.find_by_id(id, [&value](const auto&, auto &reg) {
          reg = value;
        }, [&]() {
          send_error(0x45, "No register with ID " + std::to_string(id));
        });
      }
  }, regs);
  _debugger.get_domain().set_cpu_context(regs, vcpu_id);
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::GeneralRegistersBatchReadRequest &req) const
{
  const auto thread_id = req.get_thread_id();
  const auto vcpu_id = (thread_id == (size_t)-1) ? 0 : thread_id-1;
  std::visit(util::overloaded {
      [&](const auto &regs) {
        send(rsp::GeneralRegistersBatchReadResponse(regs));
      }
  }, _debugger.get_domain().get_cpu_context(vcpu_id));
}

template <>
void GDBRequestHandler::operator()(
    const req::GeneralRegistersBatchWriteRequest &req) const
{
  auto regs_any = _debugger.get_domain().get_cpu_context(_debugger.get_vcpu_id());
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

  _debugger.get_domain().set_cpu_context(regs_any, _debugger.get_vcpu_id());

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
  _debugger.continue_();
  send(rsp::OKResponse());
}

template <>
void GDBRequestHandler::operator()(
    const req::StepRequest &) const
{
  _debugger.single_step();
}

template <>
void GDBRequestHandler::operator()(
    const req::BreakpointInsertRequest &req) const
{
  switch (req.get_type()) {
    case 0: { // Software breakpoint
      _debugger.insert_breakpoint(req.get_address());
      send(rsp::OKResponse());
    }; break;
    case 1: { // Hardware breakpoint
      send(rsp::NotSupportedResponse());
    }; break;
    case 2: { // Write watchpoint
      // 'kind' indicates the number of bytes to watch
      // set mem access to exclude writes
      _debugger.insert_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Write);
      send(rsp::OKResponse());
    }; break;
    case 3: { // Read watchpoint
      _debugger.insert_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Read);
      send(rsp::OKResponse());
    }; break;
    case 4: { // Access watchpoint
      _debugger.insert_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Access);
      send(rsp::OKResponse());
    }; break;
    default: {
      send(rsp::NotSupportedResponse());
    }; break;
  }
}

template <>
void GDBRequestHandler::operator()(
    const req::BreakpointRemoveRequest &req) const
{
  switch (req.get_type()) {
    case 0: { // Software breakpoint
      _debugger.remove_breakpoint(req.get_address());
      send(rsp::OKResponse());
    }; break;
    case 1: { // Hardware breakpoint
      send(rsp::NotSupportedResponse());
    }; break;
    case 2: { // Write watchpoint
      // 'kind' indicates the number of bytes to watch
      _debugger.remove_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Write);
      send(rsp::OKResponse());
    }; break;
    case 3: { // Read watchpoint
      _debugger.remove_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Read);
      send(rsp::OKResponse());
    }; break;
    case 4: { // Access watchpoint
      _debugger.remove_watchpoint(req.get_address(), req.get_kind(), dbg::WatchpointType::Access);
      send(rsp::OKResponse());
    }; break;
    default: {
      send(rsp::NotSupportedResponse());
    }; break;
  }
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
