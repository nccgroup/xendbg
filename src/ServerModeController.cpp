#include <iostream>

#include <GDBServer/GDBPacketInterpreter.hpp>
#include <UV/UVPoll.hpp>
#include <UV/UVSignal.hpp>

#include "ServerModeController.hpp"

using xd::gdbsrv::interpret_packet;
using xd::ServerModeController;
using xd::uv::UVLoop;
using xd::uv::UVPoll;
using xd::uv::UVSignal;
using xd::xen::get_domains;

ServerModeController::ServerModeController(uint16_t base_port)
  : _next_port(base_port)
{
}

void ServerModeController::run() {
  UVSignal signal(_loop);
  signal.start([this]() {
    _loop.stop();
  }, SIGINT);

  auto &watch_introduce = _xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto &watch_release = _xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  uv::UVPoll poll(_loop, _xenstore.get_fileno());
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
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  for (const auto &domain : domains) {
    std::visit(util::overloaded {
      [&](const xen::DomainPV &domain) {
        auto domid = domain.get_domid();
        if (!_instances.count(domid)) {
          std::cout << "[+] Domain " << domid << ": port " << _next_port << std::endl;
          auto [kv, _] = _instances.emplace(domid, Instance(_loop, domain)); // TODO
          kv->second.run("127.0.0.1", _next_port++);
        }
      },
      [&](const xen::DomainHVM &domain) {
        throw std::runtime_error("HVM domain instances not yet supported!");
      }
    }, domain);
  }
}

void ServerModeController::prune_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  auto it = _instances.begin();
  while (it != _instances.end()) {
    if (std::none_of(domains.begin(), domains.end(),
      [&](const auto &domain) {
        return std::visit(util::overloaded {
          [&](const auto &domain) {
            return domain.get_domid() == it->second.get_domid();
          }
        }, domain);
      }))
    {
      std::cout << "[-] Domain " << it->second.get_domid() << std::endl;
      it = _instances.erase(it);
    } else {
      ++it;
    }
  }
}

ServerModeController::Instance::Instance(UVLoop &loop, xen::DomainPV domain)
  : _domid(domain.get_domid()), _domain(std::move(domain)),  _server(loop),
    _debugger(new dbg::DebugSessionPV(loop, _domain))
{
}

void ServerModeController::Instance::run(const std::string& address_str, uint16_t port) {
  const auto on_error = [](int error) {
    std::cout << "Error: " << std::strerror(error) << std::endl;
  };

  _server.run(address_str, port, 1, [this, on_error](auto &server, auto &connection) {
    _debugger->attach();

    connection.start([this, &server](auto &connection, const auto &packet) {
      interpret_packet(_domain, *_debugger, server, connection, packet);
    }, [this]() {
      _debugger->detach();
    }, on_error);
  }, on_error);
}
