
//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCE_HPP
#define XENDBG_SERVERINSTANCE_HPP

#include <memory>
#include <string>

#include <uvw.hpp>

#include <Xen/Common.hpp>

namespace xd::gdbsrv {

  class GDBConnection;

  class GDBServer : std::enable_shared_from_this<GDBServer> {
  public:
    using OnAcceptFn = std::function<void(GDBServer&, GDBConnection)>;
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    explicit GDBServer(uvw::Loop &loop);
    virtual ~GDBServer() = default;

    void listen(const std::string& address, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error);

  private:
    std::shared_ptr<uvw::TcpHandle> _tcp;
  };

}

#endif //XENDBG_SERVERINSTANCE_HPP
