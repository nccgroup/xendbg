#ifndef XENDBG_GDBPACKETHANDLER_HPP
#define XENDBG_GDBPACKETHANDLER_HPP

#include <Debugger/Debugger.hpp>
#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>
#include <GDBServer/GDBRequestPacket.hpp>
#include <GDBServer/GDBRequestPacket.hpp>
#include <GDBServer/GDBResponsePacket.hpp>
#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>
#include <Xen/Domain.hpp>

namespace xd::gdbsrv {

  class GDBServer;
  class GDBConnection;

  class GDBPacketHandler {
  public:
    using OnErrorFn = std::function<void(int)>;

    GDBPacketHandler(xen::Domain &domain, dbg::Debugger &debugger,
        GDBServer &server, GDBConnection &connection)
      : _domain(domain), _debugger(debugger), _server(server),
        _connection(connection)
    {
    }

    void send(const pkt::GDBResponsePacket &packet) const {
      _connection.send(packet);
    }

    void broadcast(const pkt::GDBResponsePacket &packet) const {
      _connection.send(packet);
    }

  private:
    xen::Domain &_domain;
    xd::dbg::Debugger &_debugger;
    GDBServer &_server;
    GDBConnection &_connection;

  public:
    // Default to a "not supported" response
    // Specialize for specific supported packets
    template <typename Packet_t>
    void operator()(const Packet_t &) const {
      send(pkt::NotSupportedResponse());
    };

  };

}

#endif //XENDBG_GDBPACKETHANDLER_HPP
