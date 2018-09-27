#include <iostream>

#include <UV/UVPoll.hpp>
#include <UV/UVSignal.hpp>

#include "ServerInstancePV.hpp"
#include "Server.hpp"

using xd::Server;
using xd::ServerInstancePV;
using xd::uv::UVLoop;
using xd::uv::UVPoll;
using xd::uv::UVSignal;
using xd::xen::get_domains;

Server::Server(uint16_t base_port)
  : _next_port(base_port)
{
}

void Server::run() {
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

static xd::xen::DomID get_domid_any(const xd::xen::DomainAny &domain) {
  return std::visit(xd::util::overloaded {
    [](const auto &domain) {
      return domain.get_domid();
    },
  }, domain);
}

void Server::add_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  for (const auto &domain_any : domains) {
    const auto domid = get_domid_any(domain_any);
    if (!_instances.count(domid)) {
      std::cout << "[+] Domain " << domid << ": port " << _next_port << std::endl;
    }

    std::visit(util::overloaded {
      [&](const xen::DomainPV &domain) {
        auto [kv, _] = _instances.emplace(domid,
            std::make_unique<ServerInstancePV>(_loop, domain)); // TODO
        kv->second->run("127.0.0.1", _next_port++);
      },
      [&](const xen::DomainHVM &domain) {
        throw std::runtime_error("HVM domain instances not yet supported!");
      }
    }, domain_any);
  }
}

void Server::prune_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  auto it = _instances.begin();
  while (it != _instances.end()) {
    if (std::none_of(domains.begin(), domains.end(),
      [&](const auto &domain) {
        return get_domid_any(domain) == it->second->get_domid();
      }))
    {
      std::cout << "[-] Domain " << it->second->get_domid() << std::endl;
      it = _instances.erase(it);
    } else {
      ++it;
    }
  }
}
