#include <iostream>
#include <numeric>
#include <stdexcept>

#include "../uvcast.hpp"

#include "GDBConnection.hpp"
#include "../Util/string.hpp"

using uvcast::uv_upcast;
using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBPacket;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::util::string::is_prefix;
using xd::uv::OnErrorFn;
using xd::uv::UVTCP;

class UnknownPacketTypeException : public std::runtime_error {
public:
  explicit UnknownPacketTypeException(const std::string &data)
      : std::runtime_error(data) {};
};

GDBConnection::GDBConnection(UVTCP tcp)
  : _tcp(std::move(tcp)), _ack_mode(true), _is_initializing(false)
{
}

void GDBConnection::start(OnReceiveFn on_receive, OnCloseFn on_close,
    OnErrorFn on_error)
{
  _is_initializing = true;

  // TODO: can't capture THIS pointer here
  _tcp.read_start([this, on_receive, on_error](auto data) {
    if (_is_initializing && data.size() == 1 && data.front() == '+') {
      _tcp.write("+", on_error);
    } else {
      _input_queue.append(std::move(data));
      while (!_input_queue.empty()) {
        const auto raw_packet = _input_queue.pop();

        bool valid = validate_packet_checksum(raw_packet);

        if (_ack_mode)
          _tcp.write(valid ? "+" : "-", on_error);

        if (valid) {
          try { // TODO exception handling
            const auto packet = parse_packet(raw_packet);
            on_receive(*this, packet);
          } catch (const UnknownPacketTypeException &e) {
            send(pkt::NotSupportedResponse(), on_error);
          }
        }
      }
    }
  }, on_close, on_error);
}

void GDBConnection::stop() {
  _tcp.read_stop();
}

void GDBConnection::send(const pkt::GDBResponsePacket &packet, OnErrorFn on_error)
{
  _tcp.write(format_packet(packet), on_error);
}

bool GDBConnection::validate_packet_checksum(const GDBPacket &packet) {
  const auto& contents = packet.contents;
  const auto checksum_calculated = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  return checksum_calculated == packet.checksum;
}

std::string GDBConnection::format_packet(const GDBResponsePacket &packet) {
  const auto& contents = packet.to_string();
  const uint8_t checksum = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << contents << "#";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)checksum;

  return ss.str();
}

GDBRequestPacket GDBConnection::parse_packet(const GDBPacket &packet) {
  const auto &contents = packet.contents;

  switch (contents[0]) {
    case 'q':
      if (contents == "qfThreadInfo")
        return pkt::QueryThreadInfoStartRequest(contents);
      else if (contents == "qsThreadInfo")
        return pkt::QueryThreadInfoContinuingRequest(contents);
      else if (contents == "qC")
        return pkt::QueryCurrentThreadIDRequest(contents);
      else if (is_prefix(std::string("qSupported"), contents))
        return pkt::QuerySupportedRequest(contents);
      else if ("qHostInfo" == contents)
        return pkt::QueryHostInfoRequest(contents);
      else if ("qProcessInfo" == contents)
        return pkt::QueryProcessInfoRequest(contents);
      else if (is_prefix(std::string("qRegisterInfo"), contents))
        return pkt::QueryRegisterInfoRequest(contents);
      else if (is_prefix(std::string("qMemoryRegionInfo"), contents))
        return pkt::QueryMemoryRegionInfoRequest(contents);
      break;
    case 'Q':
      if (contents == "QStartNoAckMode")
        return pkt::StartNoAckModeRequest(contents);
      else if (contents == "QThreadSuffixSupported")
        return pkt::QueryThreadSuffixSupportedRequest(contents);
      else if (contents == "QListThreadsInStopReply")
        return pkt::QueryListThreadsInStopReplySupportedRequest(contents);
      break;
    case '?':
      return pkt::StopReasonRequest(contents);
    case 'k':
      return pkt::KillRequest(contents);
    case 'H':
      return pkt::SetThreadRequest(contents);
    case 'p':
      return pkt::RegisterReadRequest(contents);
    case 'P':
      return pkt::RegisterWriteRequest(contents);
    case 'G':
      return pkt::GeneralRegistersBatchWriteRequest(contents);
    case 'g':
      return pkt::GeneralRegistersBatchReadRequest(contents);
    case 'M':
      return pkt::MemoryWriteRequest(contents);
    case 'm':
      return pkt::MemoryReadRequest(contents);
    case 'c':
      return pkt::ContinueRequest(contents);
    case 'C':
      return pkt::ContinueSignalRequest(contents);
    case 's':
      return pkt::StepRequest(contents);
    case 'S':
      return pkt::StepSignalRequest(contents);
    case 'Z':
      return pkt::BreakpointInsertRequest(contents);
    case 'z':
      return pkt::BreakpointRemoveRequest(contents);
    case 'R':
      return pkt::RestartRequest(contents);
    case 'D':
      return pkt::DetachRequest(contents);
  }

  throw UnknownPacketTypeException(contents);
}
