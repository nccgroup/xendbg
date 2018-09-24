//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBConnection.hpp"
#include "GDBPacketInterpreter.hpp"
#include "GDBResponsePacket.hpp"
#include "../Registers/RegistersX86.hpp"
#include "../Xen/XenException.hpp"
#include "../Debugger/DebugSession.hpp"

using xd::dbg::DebugSession;
using xd::reg::RegistersX86;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::XenException;

void xd::gdbsrv::interpret_packet(
      xd::dbg::DebugSession &debugger,
      xd::gdbsrv::GDBServer &server,
      xd::gdbsrv::GDBConnection &connection,
      const xd::gdbsrv::pkt::GDBRequestPacket &packet)
{
  using namespace xd::gdbsrv::pkt;

  // TODO
  const auto on_error = [](int error) {
    std::cout << "Error: " << std::strerror(error) << std::endl;
  };

  const auto visitor = util::overloaded {
      [&](const InterruptRequest &req) {
        // TODO: actually interrupt the guest
        server.broadcast(StopReasonSignalResponse(SIGSTOP, 1), on_error); // TODO
        //connection.send(StopReasonSignalResponse(SIGSTOP, 1), on_error); // TODO
      },
      [&](const StartNoAckModeRequest &req) {
        connection.disable_ack_mode();
        connection.send(OKResponse(), on_error);
      },
      [&](const QuerySupportedRequest &req) {
        connection.send(QuerySupportedResponse({
          "PacketSize=20000",
          "QStartNoAckMode+",
          "QThreadSuffixSupported+",
          "QListThreadsInStopReplySupported+",
        }), on_error);
      },
      [&](const QueryThreadSuffixSupportedRequest &req) {
        connection.send(OKResponse(), on_error);
      },
      [&](const QueryListThreadsInStopReplySupportedRequest &req) {
        connection.send(OKResponse(), on_error);
      },
      [&](const QueryHostInfoRequest &req) {
        const auto domain = debugger.get_domain();
        const auto name = domain.get_name();
        const auto word_size = domain.get_word_size();
        connection.send(QueryHostInfoResponse(word_size, name), on_error);
      },
      [&](const QueryRegisterInfoRequest &req) {
        const auto id = req.get_register_id();
        const auto word_size = debugger.get_domain().get_word_size();

        if (word_size == sizeof(uint64_t)) {
          RegistersX86_64::find_metadata_by_id(id, [&](const auto &md) {
            connection.send(QueryRegisterInfoResponse(
                md.name, 8*md.width, md.offset, md.gcc_id), on_error);
          }, [&]() {
            connection.send(ErrorResponse(0x45), on_error);
          });
        } else if (word_size == sizeof(uint32_t)) {
          RegistersX86_32::find_metadata_by_id(id, [&](const auto &md) {
            connection.send(QueryRegisterInfoResponse(
                md.name, 8*md.width, md.offset, md.gcc_id), on_error);
          }, [&]() {
            connection.send(ErrorResponse(0x45), on_error);
          });
        } else {
          throw std::runtime_error("Unsupported word size!");
        }
      },
      [&](const QueryProcessInfoRequest &req) {
        // TODO
        connection.send(QueryProcessInfoResponse(1), on_error);
      },
      [&](const QueryMemoryRegionInfoRequest &req) {
        const auto address = req.get_address();

        try {
          const auto start = address & XC_PAGE_MASK;
          const auto size = XC_PAGE_SIZE;
          const auto perms = debugger.get_domain().get_memory_permissions(address);

          connection.send(QueryMemoryRegionInfoResponse(start, size, perms), on_error);
        } catch (const XenException &e) {
          std::string error(e.what());
          error += std::string(": ") + std::strerror(errno);
          connection.send(QueryMemoryRegionInfoErrorResponse(error), on_error);
        }
      },
      [&](const QueryCurrentThreadIDRequest &req) {
        // TODO
        connection.send(QueryCurrentThreadIDResponse(1), on_error);
      },
      [&](const QueryThreadInfoStartRequest &req) {
        connection.send(QueryThreadInfoResponse({1}), on_error);
      },
      [&](const QueryThreadInfoContinuingRequest &req) {
        connection.send(QueryThreadInfoEndResponse(), on_error);
      },
      [&](const StopReasonRequest &req) {
        server.broadcast(StopReasonSignalResponse(SIGTRAP, 1), on_error); // TODO
        //connection.send(StopReasonSignalResponse(SIGTRAP, 1), on_error); // TODO
      },
      [&](const KillRequest &req) {
        debugger.get_domain().destroy();
        server.broadcast(TerminatedResponse(SIGKILL), on_error);
        //connection.send(TerminatedResponse(SIGKILL), on_error);
      },
      [&](const SetThreadRequest &req) {
        connection.send(OKResponse(), on_error);
      },
      [&](const RegisterReadRequest &req) {
        const auto id = req.get_register_id();
        const auto thread_id = req.get_thread_id();
        const auto regs = debugger.get_domain().get_cpu_context(thread_id-1);

        std::visit(util::overloaded {
            [&](const auto &regs) {
              regs.find_by_id(id, [&](const auto& md, const auto &reg) {
                connection.send(RegisterReadResponse(reg), on_error);
              }, [&]() {
                connection.send(ErrorResponse(0x45), on_error); // TODO
              });
            }
        }, regs);
      },
      [&](const RegisterWriteRequest &req) {
        const auto id = req.get_register_id();
        const auto value = req.get_value();

        auto regs = debugger.get_domain().get_cpu_context();
        std::visit(util::overloaded {
            [&](auto &regs) {
              regs.find_by_id(id, [&value](const auto&, auto &reg) {
                reg = value;
              }, [&]() {
                connection.send(ErrorResponse(0x45), on_error); // TODO
              });
            }
        }, regs);
        debugger.get_domain().set_cpu_context(regs);
        connection.send(OKResponse(), on_error);
      },
      [&](const GeneralRegistersBatchReadRequest &req) {
        const auto regs = debugger.get_domain().get_cpu_context();
        std::visit(util::overloaded {
            [&](const auto &regs) {
              connection.send(GeneralRegistersBatchReadResponse(regs), on_error);
            }
            /*
            [&](const RegistersX86_32 &regs) {
              connection.send(GeneralRegistersBatchReadResponse(regs), on_error);
            },
            [&](const RegistersX86_64 &regs) {
              connection.send(GeneralRegistersBatchReadResponse(regs), on_error);
            }
            */
        }, regs);
      },
      [&](const GeneralRegistersBatchWriteRequest &req) {
        auto orig_regs_any = debugger.get_domain().get_cpu_context();
        auto values = req.get_values();

        std::visit(util::overloaded {
            [&values](auto &orig_regs) {
              const auto pair = values.back();
              values.pop_back();

              // For some reason, if I do [id, value] = values.back(),
              // 'value' isn't available for the lambda capture below
              const auto id = pair.first;
              const auto value = pair.second;

              orig_regs.find_by_id(id, [value](const auto&, auto &reg) {
                std::visit(util::overloaded {
                    [&reg](const auto &value) {
                      reg = value;
                    }
                }, value);
              }, [&]() {
                throw std::runtime_error("Oversized register write packet!");
              });
            }
        }, orig_regs_any);

        connection.send(pkt::OKResponse(), on_error);
      },
      [&](const MemoryReadRequest &req) {
        const auto address = req.get_address();
        const auto length = req.get_length();

        const auto data = debugger.read_memory_masking_breakpoints(address, length);
        connection.send(MemoryReadResponse(data.get(), length), on_error);
      },
      [&](const MemoryWriteRequest &req) {
        const auto address = req.get_address();
        const auto length = req.get_length();
        const auto data = req.get_data();

        debugger.write_memory_retaining_breakpoints(
            address, length, (void*)&data[0]);
        connection.send(OKResponse(), on_error);
      },
      [&](const ContinueRequest &req) {
        debugger.continue_();

        // TODO
        /*
        connection.add_timer().start([&]() {
          bool hit = debugger.check_breakpoint_hit().has_value();
          if (hit) {
            debugger.get_domain().pause();
            connection.send(StopReasonSignalResponse(SIGTRAP, 1)); // TODO
          }
          return hit;
        }, 0, 100);
        */

        connection.send(OKResponse(), on_error);
      },
      [&](const ContinueSignalRequest &req) {
        connection.send(NotSupportedResponse(), on_error);
      },
      [&](const StepRequest &req) {
        debugger.single_step();
        server.broadcast(StopReasonSignalResponse(SIGTRAP, 1), on_error);
      },
      [&](const StepSignalRequest &req) {
        connection.send(NotSupportedResponse(), on_error);
      },
      [&](const BreakpointInsertRequest &req) {
        const auto address = req.get_address();
        debugger.insert_breakpoint(address);
        connection.send(OKResponse(), on_error);
      },
      [&](const BreakpointRemoveRequest &req) {
        const auto address = req.get_address();
        debugger.remove_breakpoint(address);
        connection.send(OKResponse(), on_error);
      },
      [&](const RestartRequest &req) {
        connection.send(NotSupportedResponse(), on_error);
      },
      [&](const DetachRequest &req) {
        connection.send(OKResponse(), on_error);
        connection.stop();
      },
  };

  std::visit(visitor, packet);
}
