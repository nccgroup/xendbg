//
// Created by Spencer Michaels on 9/5/18.
//

#include <iostream>
#include <stdexcept>
#include <sstream>

#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <numeric>
#include <signal.h>
#include <unistd.h>

#include "GDBPacketIO.hpp"
#include "GDBStub.hpp"
#include "../../Util/overloaded.hpp"

using xd::dbg::gdbstub::GDBPacketIO;
using xd::dbg::gdbstub::GDBStub;
using xd::util::overloaded;

int tcp_socket_open(in_addr_t addr, int port);
int tcp_socket_accept(int sock_fd);
int receive_packet(void *buffer);

GDBStub::GDBStub(int port)
  : _address(INADDR_LOOPBACK), _port(port)
{
}

GDBStub::GDBStub(in_addr_t address, int port)
  : _address(address), _port(port)
{
}

void GDBStub::run() {
  int listen_fd = tcp_socket_open(_address, _port);
  int remote_fd = tcp_socket_accept(listen_fd);

  // TODO: clean this up
  char ack;
  const auto bytes_read = read(remote_fd, &ack, sizeof(ack));
  if (bytes_read <= 0)
    std::runtime_error("Didn't get an ack from remote!");
  if (ack != '+')
    std::runtime_error("Unexpected value.");
  write(remote_fd, &ack, sizeof(ack));

  GDBPacketIO io(remote_fd);

  bool running = true;
  while (running) {
    try {
      const auto packet = io.read_packet();
      const auto visitor = util::overloaded {
        [&io](const pkt::StartNoAckModeRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());

          /* TODO: Turning off acks is recommended to "increase throughput",
           * but in practice makes LLDB send responses much more slowly.
           * Not sure yet if this is an issue with xendbg, or with LLDB.
           *
           * See: https://github.com/llvm-mirror/lldb/blob/master/docs/lldb-gdb-remote.txt#L756
           */
          //io.write_packet(pkt::OKResponse());
          //io.set_ack_enabled(false);
        },
        [&io](const pkt::QuerySupportedRequest &req) {
          io.write_packet(pkt::QuerySupportedResponse({
            //"QStartNoAckMode+"
          }));
        },
        [&io](const pkt::QueryHostInfoRequest &req) {
          // TODO
          io.write_packet(pkt::QueryHostInfoResponse(64, "guest"));
        },
        [&io](const pkt::QueryRegisterInfoRequest &req) {
          // TODO
          auto i = req.get_register_id();
          if (i < 14) {
            std::string name("reg");
            name += std::to_string(i);
            io.write_packet(pkt::QueryRegisterInfoResponse(name, 64, i, i));
          } else {
            io.write_packet(pkt::ErrorResponse(0x45));
          }
        },
        [&io](const pkt::QueryProcessInfoRequest &req) {
          // TODO
          io.write_packet(pkt::QueryProcessInfoResponse(1));
        },
        [&io](const pkt::QueryCurrentThreadIDRequest &req) {
          // TODO
          io.write_packet(pkt::QueryCurrentThreadIDResponse(1));
        },
        [&io](const pkt::QueryThreadInfoStartRequest &req) {
          io.write_packet(pkt::QueryThreadInfoResponse({0}));
        },
        [&io](const pkt::QueryThreadInfoContinuingRequest &req) {
          io.write_packet(pkt::QueryThreadInfoEndResponse());
        },
        [&io](const pkt::StopReasonRequest &req) {
          io.write_packet(pkt::StopReasonSignalResponse(0x05));
        },
        [&io](const pkt::SetThreadRequest &req) {
          io.write_packet(pkt::OKResponse());
        },
        [&io](const pkt::RegisterReadRequest &req) {
          // TODO
          io.write_packet(pkt::RegisterReadResponse(0xDEADBEEF));
        },
        [&io](const pkt::RegisterWriteRequest &req) {
          io.write_packet(pkt::OKResponse());
        },
        [&io](const pkt::GeneralRegistersBatchReadRequest &req) {
          // TODO
          GDBRegisters64 dummy_regs;
          memset((void*)&dummy_regs, 0x00, sizeof(dummy_regs));
          dummy_regs.values.rax = 0xEFBEADDEEFBEADDE;
          dummy_regs.values.rflags = 0xEFBEADDE;
          dummy_regs.values.gs = 0xEFBEADDE;
          io.write_packet(pkt::GeneralRegistersBatchReadResponse(dummy_regs));
        },
        [&io](const pkt::GeneralRegistersBatchWriteRequest &req) {
          io.write_packet(pkt::OKResponse());
        },
        [&io](const pkt::MemoryReadRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::MemoryWriteRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::ContinueRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::ContinueSignalRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::StepRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::StepSignalRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::BreakpointInsertRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::BreakpointRemoveRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::RestartRequest &req) {
          io.write_packet(pkt::NotSupportedResponse());
        },
        [&io](const pkt::DetachRequest &req) {
          io.write_packet(pkt::OKResponse());
        },
      };

      std::visit(visitor, packet);

    } catch (const UnknownPacketTypeException &e) {
      std::cout << "[!] Unrecognized packet: ";
      std::cout << e.what() << std::endl;
      io.write_packet(pkt::NotSupportedResponse());
    }
  }
}

int GDBStub::tcp_socket_open(in_addr_t addr, int port) {
  int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)
    throw std::runtime_error("Failed to open socket!");

  socklen_t tmp;
  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof(tmp));

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = PF_INET;
  sockaddr.sin_port = htons(port);
  sockaddr.sin_addr.s_addr = htonl(addr);

  if (bind(sock_fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) {
    close(sock_fd);
    throw std::runtime_error("Failed to bind socket!");
  }
  if (listen(sock_fd, 1)) {
    close(sock_fd);
    throw std::runtime_error("Failed to listen on socket!");
  }

  return sock_fd;
}


int GDBStub::tcp_socket_accept(int sock_fd) {
  if (sock_fd < 0)
    throw std::runtime_error("Invalid socket FD!");

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));

  socklen_t tmp;
  int remote_fd = accept(sock_fd, (struct sockaddr*)&sockaddr, &tmp);
  if (remote_fd < 0) {
    close(sock_fd);
    throw std::runtime_error("Failed to accept!");
  }

  // Instruct TCP not to delay small packets. This improves interactivity.
  tmp = 1;
  setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&tmp, sizeof(tmp));
  close(sock_fd);

  // Don't exit automatically when the remote side does
  signal(SIGPIPE, SIG_IGN);

  return remote_fd;
}
