#include <iostream>
#include <numeric>
#include <stdexcept>

#include <spdlog/spdlog.h>

#include <Globals.hpp>
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
  : _tcp(std::move(tcp)), _ack_mode(true), _is_initializing(false), _error_strings(false)
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
      spdlog::get(LOGNAME_CONSOLE)->debug("Got initial ACK.");
      self->_is_initializing = false;
      tcp.write(ACK_OK, 1);
    } else {
      self->_input_queue.append(std::move(data));
      while (!self->_input_queue.empty()) {
        const auto raw_packet = self->_input_queue.pop();

        bool valid = raw_packet.is_checksum_valid();

        if (self->_ack_mode) {
          tcp.write(valid ? ACK_OK : ACK_ERROR, 1);
          spdlog::get(LOGNAME_CONSOLE)->debug("ACK: {0}", valid ? "OK": "error");
        }

        if (valid) {
          try {
            spdlog::get(LOGNAME_CONSOLE)->debug("RECV: {0}", raw_packet.to_string());
            const auto packet = parse_packet(raw_packet);
            on_receive(*self, packet);
          } catch (const UnknownPacketTypeException &e) {
            spdlog::get(LOGNAME_ERROR)->warn(
              "Got packet of unknown type: \"{0}\"", e.what());
            self->send(rsp::NotSupportedResponse());
          } catch (const req::RequestPacketParseException &e) {
            spdlog::get(LOGNAME_ERROR)->error(
                "Failed to parse packet ({0}): \"{1}\"",
                e.what(), raw_packet.get_contents());
            self->send(rsp::NotSupportedResponse());
          }
        } else {
          spdlog::get(LOGNAME_ERROR)->warn(
              "Invalid checksum for packet: \"{0}\"", raw_packet.get_contents());
        }
      }
    }
  });

  _tcp->read();
}

void GDBConnection::stop() {
  if (!_tcp->closing())
    _tcp->stop();
}

void GDBConnection::send(const rsp::GDBResponse &packet)
{
  const auto raw_packet = GDBPacket(packet.to_string());
  const auto &contents = raw_packet.to_string();

  spdlog::get(LOGNAME_CONSOLE)->debug("SEND: {0}", contents);

  _tcp->write((char*)contents.c_str(), contents.size());
}

void GDBConnection::send_error(uint8_t code, std::string message) {
  if (_error_strings)
    send(rsp::ErrorResponse(code, std::move(message)));
  else
    send(rsp::ErrorResponse(code));
}

template <typename T>
static auto make_parser() {
  return [](const auto &s) { return T(s); };
}

GDBRequest GDBConnection::parse_packet(const GDBPacket &packet) {
  using namespace xd::gdb::req;
  using ParseRequestFn = std::function<GDBRequest(const std::string&)>;

  static const std::vector<std::pair<std::string, ParseRequestFn>> request_parsers = {
      { "qfThreadInfo",             make_parser<QueryThreadInfoStartRequest>() },
      { "qsThreadInfo",             make_parser<QueryThreadInfoContinuingRequest>() },
      { "qC",                       make_parser<QueryCurrentThreadIDRequest>() },
      { "qWatchpointSupportInfo", make_parser<QueryWatchpointSupportInfo>() },
      { "qSupported",               make_parser<QuerySupportedRequest>() },
      { "qHostInfo",                make_parser<QueryHostInfoRequest>() },
      { "qProcessInfo",             make_parser<QueryProcessInfoRequest>() },
      { "qRegisterInfo",            make_parser<QueryRegisterInfoRequest>() },
      { "qMemoryRegionInfo",        make_parser<QueryMemoryRegionInfoRequest>() },
      { "QStartNoAckMode",          make_parser<StartNoAckModeRequest>() },
      { "QThreadSuffixSupported",   make_parser<QueryThreadSuffixSupportedRequest>() },
      { "QListThreadsInStopReply",  make_parser<QueryListThreadsInStopReplySupportedRequest>() },
      { "QEnableErrorStrings",      make_parser<QueryEnableErrorStrings>() },
      { "\x03",                     make_parser<InterruptRequest>() },
      { "?",                        make_parser<StopReasonRequest>() },
      { "k",                        make_parser<KillRequest>() },
      { "H",                        make_parser<SetThreadRequest>() },
      { "p",                        make_parser<RegisterReadRequest>() },
      { "P",                        make_parser<RegisterWriteRequest>() },
      { "g",                        make_parser<GeneralRegistersBatchReadRequest>() },
      { "G",                        make_parser<GeneralRegistersBatchWriteRequest>() },
      { "m",                        make_parser<MemoryReadRequest>() },
      { "M",                        make_parser<MemoryWriteRequest>() },
      { "c",                        make_parser<ContinueRequest>() },
      { "C",                        make_parser<ContinueSignalRequest>() },
      { "s",                        make_parser<StepRequest>() },
      { "S",                        make_parser<StepSignalRequest>() },
      { "z",                        make_parser<BreakpointRemoveRequest>() },
      { "Z",                        make_parser<BreakpointInsertRequest>() },
      { "R",                        make_parser<RestartRequest>() },
      { "D",                        make_parser<DetachRequest>() },
  };

  for (const auto &pair : request_parsers)
    if (packet.starts_with(pair.first))
      return pair.second(packet.get_contents());

  throw UnknownPacketTypeException(packet.get_contents());
}
