#include "GDBServerInstancePV.hpp"
#include "GDBPacketHandler.hpp"

using xd::ServerInstancePV;

ServerInstancePV::ServerInstancePV(uv::UVLoop &loop, xen::DomainPV domain)
  : _domain(std::move(domain)), _debugger(loop, _domain), _server(loop)
{
};

void ServerInstancePV::run(const std::string& address_str, uint16_t port) {
  const auto on_error = [](int error) {
    std::cout << "Error: " << std::strerror(error) << std::endl;
  };

  _server.run(address_str, port, 1, [this, on_error](auto &server, auto &connection) {
    _debugger.attach();

    _packet_handler.emplace(_domain, _debugger, server, connection);
    connection.start([this, &server](auto &connection, const auto &packet) {
      std::visit(*_packet_handler, packet);
    }, [this]() {
      _debugger.detach();
      _packet_handler.reset();
    }, on_error);
  }, on_error);
}
