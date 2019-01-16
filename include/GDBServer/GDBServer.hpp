//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
    ~GDBServer();

    void stop();
    void listen(const std::string& address_str, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error);

  private:
    std::shared_ptr<uvw::TcpHandle> _server;
    OnAcceptFn _on_accept;
    OnErrorFn _on_error;
  };

}

#endif //XENDBG_GDBSERVER_HPP
