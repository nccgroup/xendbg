
//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_GDBSERVER_HPP
#define XENDBG_GDBSERVER_HPP

#include <memory>
#include <string>

#include <uvw.hpp>

#include <Xen/Common.hpp>

namespace xd::gdb {

  class GDBConnection;

  class GDBServer : public std::enable_shared_from_this<GDBServer> {
  public:
    using OnAcceptFn = std::function<void(GDBServer&, std::shared_ptr<GDBConnection>)>;
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    explicit GDBServer(uvw::Loop &loop);

    void listen(const std::string& address_str, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error);

  private:
    std::shared_ptr<uvw::TcpHandle> _server;
  };

}

#endif //XENDBG_GDBSERVER_HPP
