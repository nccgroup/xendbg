//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCEPV_HPP
#define XENDBG_SERVERINSTANCEPV_HPP

#include <optional>

#include <uvw.hpp>

#include <Debugger/DebuggerPV.hpp>
#include <GDBServer/GDBServer.hpp>

#include "GDBServer/GDBPacketHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd {

  class DebugSessionBase {
  public:
    virtual ~DebugSessionBase() = default;
    virtual void run(const std::string& address_str, uint16_t port) = 0;
  };

  template <typename Debugger_t, typename PacketHandler_t, typename Domain_t>
  class DebugSession : public DebugSessionBase {
  public:
    DebugSession(uvw::Loop &loop, Domain_t domain)
        : _domain(std::move(domain)),
          _debugger(std::make_shared<Debugger_t>(loop, _domain)),
          _gdb_server(std::make_shared<gdb::GDBServer>(loop))
    {
    };

    void run(const std::string& address_str, uint16_t port) override {
      const auto on_error = [](auto error) {
        std::cout << "Error: " << error.what() << std::endl;
      };

      _gdb_server->listen(address_str, port,
        [this, on_error](auto &server, auto connection) {
          _gdb_connection = connection;
          _debugger->attach();

          _packet_handler.emplace(_domain, *_debugger, *_gdb_server, *_gdb_connection);
          connection->read([this, &server](auto &connection, const auto &packet) {
            try {
              std::visit(*_packet_handler, packet);
            } catch (const xen::XenException &e) {
              connection.send_error(e.get_err(), e.what());
            }
          }, [this]() {
            _debugger->detach();
            _packet_handler.reset();
          }, on_error);
        }, on_error);
    }
  private:
    Domain_t _domain;
    std::shared_ptr<Debugger_t> _debugger;
    std::shared_ptr<xd::gdb::GDBServer> _gdb_server;
    std::shared_ptr<xd::gdb::GDBConnection> _gdb_connection;
    std::optional<PacketHandler_t> _packet_handler;
  };

  using DebugSessionPV = DebugSession<dbg::DebuggerPV, gdb::GDBPacketHandler, xen::DomainPV>;

}

#endif //XENDBG_SERVERINSTANCEPV_HPP
