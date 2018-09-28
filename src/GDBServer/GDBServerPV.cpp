#include <GDBServer/GDBServerPV.hpp>
#include <GDBServer/GDBPacketHandler.hpp>

using xd::gdbsrv::GDBServerPV;

GDBServerPV::GDBServerPV(uvw::Loop &loop, xen::DomainPV domain)
  : GDBServer(loop), _domain(std::move(domain)), _debugger(loop, _domain)
{
};

void GDBServerPV::run(const std::string& address_str, uint16_t port) {
  const auto on_error = [](int error) {
    std::cout << "Error: " << std::strerror(error) << std::endl;
  };

  listen(address_str, port, [this, on_error](auto &server, auto &connection) {
    _debugger.attach();

    _packet_handler.emplace(_domain, _debugger, server, connection);
    connection.read([this, &server](auto &connection, const auto &packet) {
      std::visit(*_packet_handler, packet);
    }, [this]() {
      _debugger.detach();
      _packet_handler.reset();
    }, on_error);
  }, on_error);
}
