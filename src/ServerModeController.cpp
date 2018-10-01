#include <csignal>
#include <iostream>

#include "DebugSession.hpp"
#include "ServerModeController.hpp"

using xd::ServerModeController;
using xd::DebugSession;
using xd::xen::get_domid_any;
using xd::xen::get_domains;

ServerModeController::ServerModeController(uint16_t base_port)
  : _loop(uvw::Loop::getDefault()),
    _signal(_loop->resource<uvw::SignalHandle>()),
    _poll(_loop->resource<uvw::PollHandle>(_xenstore.get_fileno())),
    _next_port(base_port)
{
}

void ServerModeController::run_single(xen::DomID domid) {
  auto domain = xen::init_domain(domid, _xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);
  add_instance(std::move(domain));
  run();
}

void ServerModeController::run_multi() {
  auto &watch_introduce = _xenstore.add_watch();
  watch_introduce.add_path("@introduceDomain");

  auto &watch_release = _xenstore.add_watch();
  watch_release.add_path("@releaseDomain");

  _poll->on<uvw::PollEvent>([&](const auto &event, auto &handle) {
    if (watch_introduce.check())
      add_new_instances();
    else if (watch_release.check())
      prune_instances();
  });

  _poll->start(uvw::PollHandle::Event::READABLE);

  run();
}

void ServerModeController::run() {
  _signal->once<uvw::SignalEvent>([](const auto &event, auto &handle) {
    handle.loop().stop();
  });
  
  _signal->start(SIGINT);

  _loop->run();
}

void ServerModeController::add_new_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  for (const auto &domain_any : domains) {
    const auto domid = get_domid_any(domain_any);
    if (!_instances.count(domid))
      add_instance(domain_any);
  }
}

void ServerModeController::prune_instances() {
  const auto domains = get_domains(_xenevtchn, _xenctrl, _xenforeignmemory, _xenstore);

  auto it = _instances.begin();
  while (it != _instances.end()) {
    if (std::none_of(domains.begin(), domains.end(),
      [&](const auto &domain) {
        return get_domid_any(domain) == it->first;
      }))
    {
      std::cout << "[-] Domain " << it->first << std::endl;
      it = _instances.erase(it);
    } else {
      ++it;
    }
  }
}

void ServerModeController::add_instance(xen::DomainAny domain_any) {
  const auto domid = get_domid_any(domain_any);

  if (_instances.count(domid))
    throw DomainAlreadyAddedException(domid);

  std::visit(util::overloaded {
      [&](xen::DomainPV domain) {
        auto [kv, _] = _instances.emplace(domid,
            std::make_unique<DebugSessionPV>(*_loop, std::move(domain))); // TODO

        std::cout << "[+] Domain " << kv->first << ": port " << _next_port << std::endl;
        kv->second->run("127.0.0.1", _next_port++);
      },
      [&](xen::DomainHVM domain) {
        throw std::runtime_error("HVM domain instances not yet supported!");
      }
  }, domain_any);
}
