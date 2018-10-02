#ifndef XENDBG_GDBREQUESTHANDLER_HPP
#define XENDBG_GDBREQUESTHANDLER_HPP

#include <Debugger/Debugger.hpp>
#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>
#include <GDBServer/GDBRequest/GDBRequest.hpp>
#include <GDBServer/GDBResponse/GDBResponse.hpp>
#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>
#include <Xen/Domain.hpp>

namespace xd::gdb {

  class PacketSizeException : public std::exception {
  public:
    PacketSizeException(size_t actual_size, size_t expected_size)
      : _actual_size(actual_size),_expected_size(expected_size) {}

    size_t get_expected_size() { return _expected_size; };
    size_t get_actual_size() { return _actual_size; };

  private:
    size_t _actual_size;
    size_t _expected_size;
  };

  class WordSizeException : public std::exception {
  public:
    explicit WordSizeException(size_t word_size)
      : _word_size(word_size) {}

    size_t get_word_size() { return _word_size; };

  private:
    size_t _word_size;
  };

  class GDBServer;
  class GDBConnection;

  class GDBRequestHandler {
  public:
    using OnErrorFn = std::function<void(int)>;

    GDBRequestHandler(xen::Domain &domain, dbg::Debugger &debugger, GDBServer &server, GDBConnection &connection)
      : _domain(domain), _debugger(debugger), _server(server), _connection(connection)
    {
    }

    void send_error(uint8_t code, std::string message = "") const {
      _connection.send_error(code, std::move(message));
    }

    void send(const rsp::GDBResponse &packet) const {
      _connection.send(packet);
    }

    void broadcast(const rsp::GDBResponse &packet) const {
      _connection.send(packet);
    }

  private:
    xd::xen::Domain &_domain;
    xd::dbg::Debugger &_debugger;
    GDBServer &_server;
    GDBConnection &_connection;

  public:
    // Default to a "not supported" response
    // Specialize for specific supported packets
    template <typename Packet_t>
    void operator()(const Packet_t &) const {
      send(rsp::NotSupportedResponse());
    };

  };

}

#endif //XENDBG_GDBREQUESTHANDLER_HPP
