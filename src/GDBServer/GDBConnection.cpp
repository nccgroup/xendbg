#include <iostream>
#include <numeric>
#include <stdexcept>

#include <GDBServer/GDBConnection.hpp>
#include <Util/string.hpp>

using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBPacket;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::util::string::is_prefix;

static char ACK_OK[] = "+";
static char ACK_ERROR[] = "+";

class UnknownPacketTypeException : public std::runtime_error {
public:
  explicit UnknownPacketTypeException(const std::string &data)
      : std::runtime_error(data) {};
};

GDBConnection::GDBConnection(std::shared_ptr<uvw::TcpHandle> tcp)
  : _tcp(tcp), _ack_mode(true), _is_initializing(false)
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
            self->send(pkt::NotSupportedResponse());
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

void GDBConnection::send(const pkt::GDBResponsePacket &packet)
{
  std::cout << "SEND: " << packet.to_string() << std::endl;

  const auto s = format_packet(packet);
  _tcp->write((char*)s.c_str(), s.size());
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
    case '\x03':
      return pkt::InterruptRequest(contents);
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
    default:
      throw UnknownPacketTypeException(contents);
  }

  throw UnknownPacketTypeException(contents);
}
