#include <csignal>
#include <iostream>

#include "ServerInstancePV.hpp"
#include "Server.hpp"

using xd::Server;
using xd::ServerInstancePV;
using xd::xen::get_domains;

static xd::xen::DomID get_domid_any(const xd::xen::DomainAny &domain);

Server::Server(uint16_t base_port)
  : _loop(uvw::Loop::getDefault()),
    _poll(_loop->resource<uvw::PollHandle>(_xenstore.get_fileno())),
    _signal(_loop->resource<uvw::SignalHandle>()),
    _next_port(base_port)
{
}

void Server::run_single(xen::DomainAny domain) {
  add_instance(std::move(domain));
  run();
}

void Server::run_multi() {
  auto &watch_introduce = _xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto &watch_release = _xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  _poll->on<uvw::PollEvent>([&](const auto &event, auto &handle) {
    if (watch_introduce.check())
      add_new_instances();
    else if (watch_release.check())
      prune_instances();
  }, uvw::PollHandle::Event::READABLE);

  run();
}

void Server::run() {
  _signal->on([&](const auto &event, auto &handle) {
    _loop->stop();
  }, SIGINT);

  _loop->run();
}

void Server::add_new_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  for (const auto &domain_any : domains) {
    const auto domid = get_domid_any(domain_any);
    if (!_instances.count(domid))
      add_instance(domain_any);
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

void Server::add_instance(xen::DomainAny domain_any) {
  const auto domid = get_domid_any(domain_any);

  if (_instances.count(domid))
    throw std::runtime_error("Domain already added!");

  std::visit(util::overloaded {
      [&](xen::DomainPV domain) {
        auto [kv, _] = _instances.emplace(domid,
            std::make_unique<ServerInstancePV>(_loop, domain)); // TODO
        kv->second->run("127.0.0.1", _next_port++);
      },
      [&](xen::DomainHVM domain) {
        throw std::runtime_error("HVM domain instances not yet supported!");
      }
  }, domain_any);
}

static xd::xen::DomID get_domid_any(const xd::xen::DomainAny &domain) {
  return std::visit(xd::util::overloaded {
    [](const auto &domain) {
      return domain.get_domid();
    },
  }, domain);
}
