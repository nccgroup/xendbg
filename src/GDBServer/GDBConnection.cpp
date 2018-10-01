#include <iostream>
#include <numeric>
#include <stdexcept>

#include <GDBServer/GDBConnection.hpp>
#include <Util/string.hpp>

using xd::gdb::GDBConnection;
using xd::gdb::GDBPacket;
using xd::gdb::req::GDBRequest;
using xd::gdb::rsp::GDBResponse;
using xd::util::string::is_prefix;

static char ACK_OK[] = "+";
static char ACK_ERROR[] = "-";

GDBConnection::GDBConnection(std::shared_ptr<uvw::TcpHandle> tcp)
  : _tcp(tcp), _ack_mode(true), _is_initializing(false), _error_strings(false)
{
}

void GDBConnection::read(OnReceiveFn on_receive, OnCloseFn on_close,
    OnErrorFn on_error)
{
  _tcp->data(shared_from_this());

  _is_initializing = true;

  _tcp->on<uvw::ErrorEvent>([on_error](const auto &event, auto &tcp) {
    on_error(event);
    tcp.close();
  });

  _tcp->on<uvw::CloseEvent>([on_close](const auto &event, auto &tcp) {
    on_close();
  });

  /*
  _tcp->on<uvw::ConnectEvent>([](const auto &error) {
  });
  */

  _tcp->template on<uvw::DataEvent>([on_receive](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBConnection>();

    std::vector<char> data(event.data.get(), event.data.get() + event.length);

    if (self->_is_initializing && data.size() == 1 && data.front() == '+') {
      tcp.write(ACK_OK, 1);
    } else {
      self->_input_queue.append(std::move(data));
      while (!self->_input_queue.empty()) {
        const auto raw_packet = self->_input_queue.pop();

        bool valid = validate_packet_checksum(raw_packet);

        if (self->_ack_mode)
          tcp.write(valid ? ACK_OK : ACK_ERROR, 1);

        if (valid) {
          try { // TODO exception handling
            std::cout << "RECV: " << raw_packet.contents << std::endl;
            const auto packet = parse_packet(raw_packet);
            on_receive(*self, packet);
          } catch (const UnknownPacketTypeException &e) {
            self->send(rsp::NotSupportedResponse());
          }
        }
      }
    }
  });

  _tcp->read();
}

void GDBConnection::stop() {
  _tcp->stop();
}

void GDBConnection::send(const rsp::GDBResponse &packet)
{
  std::cout << "SEND: " << packet.to_string() << std::endl;

  const auto s = format_packet(packet);
  _tcp->write((char*)s.c_str(), s.size());
}

void GDBConnection::send_error(uint8_t code, std::string message) {
  if (_error_strings)
    send(rsp::ErrorResponse(code, message));
  else
    send(rsp::ErrorResponse(code, message));
}

bool GDBConnection::validate_packet_checksum(const GDBPacket &packet) {
  const auto& contents = packet.contents;
  const auto checksum_calculated = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  return checksum_calculated == packet.checksum;
}

std::string GDBConnection::format_packet(const GDBResponse &packet) {
  const auto& contents = packet.to_string();
  const uint8_t checksum = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << contents << "#";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)checksum;

  return ss.str();
}

GDBRequest GDBConnection::parse_packet(const GDBPacket &packet) {
  const auto &contents = packet.contents;

  switch (contents[0]) {
    case '\x03':
      return req::InterruptRequest(contents);
    case 'q':
      if (contents == "qfThreadInfo")
        return req::QueryThreadInfoStartRequest(contents);
      else if (contents == "qsThreadInfo")
        return req::QueryThreadInfoContinuingRequest(contents);
      else if (contents == "qC")
        return req::QueryCurrentThreadIDRequest(contents);
      else if (is_prefix(std::string("qSupported"), contents))
        return req::QuerySupportedRequest(contents);
      else if ("qHostInfo" == contents)
        return req::QueryHostInfoRequest(contents);
      else if ("qProcessInfo" == contents)
        return req::QueryProcessInfoRequest(contents);
      else if (is_prefix(std::string("qRegisterInfo"), contents))
        return req::QueryRegisterInfoRequest(contents);
      else if (is_prefix(std::string("qMemoryRegionInfo"), contents))
        return req::QueryMemoryRegionInfoRequest(contents);
      break;
    case 'Q':
      if (contents == "QStartNoAckMode")
        return req::StartNoAckModeRequest(contents);
      else if (contents == "QThreadSuffixSupported")
        return req::QueryThreadSuffixSupportedRequest(contents);
      else if (contents == "QListThreadsInStopReply")
        return req::QueryListThreadsInStopReplySupportedRequest(contents);
      else if (contents == "QEnableErrorStrings")
        return req::QueryEnableErrorStrings(contents);
      break;
    case '?':
      return req::StopReasonRequest(contents);
    case 'k':
      return req::KillRequest(contents);
    case 'H':
      return req::SetThreadRequest(contents);
    case 'p':
      return req::RegisterReadRequest(contents);
    case 'P':
      return req::RegisterWriteRequest(contents);
    case 'G':
      return req::GeneralRegistersBatchWriteRequest(contents);
    case 'g':
      return req::GeneralRegistersBatchReadRequest(contents);
    case 'M':
      return req::MemoryWriteRequest(contents);
    case 'm':
      return req::MemoryReadRequest(contents);
    case 'c':
      return req::ContinueRequest(contents);
    case 'C':
      return req::ContinueSignalRequest(contents);
    case 's':
      return req::StepRequest(contents);
    case 'S':
      return req::StepSignalRequest(contents);
    case 'Z':
      return req::BreakpointInsertRequest(contents);
    case 'z':
      return req::BreakpointRemoveRequest(contents);
    case 'R':
      return req::RestartRequest(contents);
    case 'D':
      return req::DetachRequest(contents);
    default:
      throw UnknownPacketTypeException(contents);
  }

  throw UnknownPacketTypeException(contents);
}
