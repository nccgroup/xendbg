#include <iostream>

#include "GDBServer/GDBPacketInterpreter.hpp"
#include "ServerModeController.hpp"
#include "UV/UVPoll.hpp"
#include "UV/UVSignal.hpp"

using xd::gdbsrv::interpret_packet;
using xd::ServerModeController;
using xd::uv::UVLoop;
using xd::uv::UVPoll;
using xd::uv::UVSignal;
using xd::xen::get_domains;

ServerModeController::ServerModeController(uint16_t base_port)
  : _xen(new xen::XenHandle()), _next_port(base_port)
{
}

void ServerModeController::run() {
  UVSignal signal(_loop);
  signal.start([this]() {
    _loop.stop();
  }, SIGINT);

  auto &xenstore = _xen->get_xenstore();

  auto &watch_introduce = xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto &watch_release = xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  uv::UVPoll poll(_loop, xenstore.get_fileno());
  poll.start([&](const auto &event) {
    if (event.readable) {
      if (watch_introduce.check())
        add_instances();
      else if (watch_release.check())
        prune_instances();
    }
  });

  _loop.start();
}

void ServerModeController::add_instances() {
  const auto domains = get_domains(_xen);

  std::for_each(domains.begin(), domains.end(),
    [&](const auto &domain) {
      const auto domid = domain.get_domid();
      if (!_instances.count(domid)) {
        std::cout << "[+] Domain " << domid << ": port " << _next_port << std::endl;
        auto [kv, _] = _instances.emplace(domid, Instance(_loop, domain));
        kv->second.run("127.0.0.1", _next_port++);
      }
    });
}

void ServerModeController::prune_instances() {
  const auto domains = get_domains(_xen);

  auto it = _instances.begin();
  while (it != _instances.end()) {
    if (std::none_of(domains.begin(), domains.end(),
      [&](const auto &domain) {
        return domain.get_domid() == it->second.get_domid();
      }))
    {
      std::cout << "[-] Domain " << it->second.get_domid() << std::endl;
      it = _instances.erase(it);
    } else {
      ++it;
    }
  }
}

ServerModeController::Instance::Instance(UVLoop &loop, xen::Domain domain)
  : _domid(domain.get_domid()),  _server(loop),
    _debugger(new dbg::DebugSessionPV(std::move(domain)))
{
}

void ServerModeController::Instance::run(const std::string& address_str, uint16_t port) {
  _server.run(address_str, port, 1, [this](auto &connection) {
    _debugger->attach();

    connection.start([this](auto &connection, const auto &packet) {
      interpret_packet(*_debugger, connection, packet);
    }, [this]() {
      _debugger->detach();
    }, []() {
      std::cout << "Error!" << std::endl; // TODO
    });
  });
}
