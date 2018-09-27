#ifndef XENDBG_GDBPACKETHANDLER_HPP
#define XENDBG_GDBPACKETHANDLER_HPP

#include <Debugger/DebugSession.hpp>
#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>
#include <GDBServer/GDBRequestPacket.hpp>
#include <GDBServer/GDBRequestPacket.hpp>
#include <GDBServer/GDBResponsePacket.hpp>
#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>
#include <Xen/Domain.hpp>

namespace xd {

  namespace dbg {
    class DebugSession;
  }
  namespace gdbsrv {
    class GDBServer;
    class GDBConnection;
  }

  class GDBPacketHandler {
  public:
    using OnErrorFn = std::function<void(int)>;

    GDBPacketHandler(xen::Domain &domain, dbg::DebugSession &debugger,
        gdbsrv::GDBServer &server, gdbsrv::GDBConnection &connection)
      : _domain(domain), _debugger(debugger), _server(server),
        _connection(connection),
        _on_error([this](int error) {
          _connection.send(
              gdbsrv::pkt::ErrorResponse(error),
              [](int){ /* do nothing */ });
        })
    {
    }

    void send(const gdbsrv::pkt::GDBResponsePacket &packet) const {
      _connection.send(packet, _on_error);
    }

    void broadcast(const gdbsrv::pkt::GDBResponsePacket &packet) const {
      _connection.send(packet, _on_error);
    }

  private:
    xen::Domain &_domain;
    dbg::DebugSession &_debugger;
    gdbsrv::GDBServer &_server;
    gdbsrv::GDBConnection &_connection;
    OnErrorFn _on_error;

  public:
    // Default to a "not supported" response
    // Specialize for specific supported packets
    template <typename Packet_t>
    void operator()(const Packet_t &) const {
      send(gdbsrv::pkt::NotSupportedResponse());
    };

  };

}

#endif //XENDBG_GDBPACKETHANDLER_HPP
