
//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCE_HPP
#define XENDBG_SERVERINSTANCE_HPP

#include <memory>
#include <string>

#include <uvw.hpp>

#include <GDBServer/GDBConnection.hpp>
#include <Xen/Common.hpp>

namespace xd::gdbsrv {

  class GDBConnection;

  class GDBServer : std::enable_shared_from_this<GDBServer> {
  public:
    using OnAcceptFn = std::function<void(GDBServer&, GDBConnection&)>;
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    explicit GDBServer(uvw::Loop &loop);
    virtual ~GDBServer() = default;

    virtual void run(const std::string& address_str, uint16_t port) = 0;

  protected:
    void listen(const std::string& address, uint16_t port,
        OnAcceptFn on_accept, OnErrorFn on_error);

  private:
    std::shared_ptr<uvw::TcpHandle> _server;
    std::unique_ptr<GDBConnection> _connection;
  };

}

#endif //XENDBG_SERVERINSTANCE_HPP
