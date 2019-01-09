//
// Copyright (C) 2018-2019 Spencer Michaels
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

//
// Created by Spencer Michaels on 9/28/18.
//

#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>

using xd::gdb::GDBServer;

GDBServer::GDBServer(uvw::Loop &loop)
  : _server(loop.resource<uvw::TcpHandle>())
{
}

GDBServer::~GDBServer() {
  stop();
}

void GDBServer::stop() {
  if (!_server->closing())
    _server->close();
}

void GDBServer::listen(const std::string &address, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error) {
  _on_accept = std::move(on_accept);
  _on_error = std::move(on_error);

  _server->data(shared_from_this());

  _server->once<uvw::ErrorEvent>([](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBServer>();
    self->_on_error(event);
  });

  // Only accept one connection; LLDB doesn't handle multiple clients attached to she same stub
  _server->once<uvw::ListenEvent>([](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBServer>();
    auto client = tcp.loop().template resource<uvw::TcpHandle>();

    client->template on<uvw::CloseEvent>(
        [ptr = tcp.shared_from_this()](const auto&, auto&) { ptr->close(); });
    client->template on<uvw::EndEvent>(
        [](const auto&, auto &client) { client.close(); });

    tcp.accept(*client);

    self->_on_accept(*self, std::make_shared<GDBConnection>(client));
  });

  _server->bind(address, port);
  _server->listen();
}
