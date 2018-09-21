//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBServer.hpp"
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
      const xd::gdbsrv::GDBServer::ClientHandle &client,
      const xd::gdbsrv::pkt::GDBRequestPacket &packet,
      xd::dbg::DebugSession &debugger)
{
  using namespace xd::gdbsrv::pkt;

  try {
    const auto visitor = util::overloaded {
        [&](const InterruptRequest &req) {
          // TODO: actually interrupt the guest
          client.send(StopReasonSignalResponse(SIGSTOP, 1)); // TODO
        },
        [&](const StartNoAckModeRequest &req) {
          client.disable_ack_mode();
          client.send(OKResponse());
        },
        [&](const QuerySupportedRequest &req) {
          client.send(QuerySupportedResponse({
            "PacketSize=20000",
            "QStartNoAckMode+",
            "QThreadSuffixSupported+",
            "QListThreadsInStopReplySupported+",
          }));
        },
        [&](const QueryThreadSuffixSupportedRequest &req) {
          client.send(OKResponse());
        },
        [&](const QueryListThreadsInStopReplySupportedRequest &req) {
          client.send(OKResponse());
        },
        [&](const QueryHostInfoRequest &req) {
          const auto domain = debugger.get_domain();
          const auto name = domain.get_name();
          const auto word_size = domain.get_word_size();
          client.send(QueryHostInfoResponse(word_size, name));
        },
        [&](const QueryRegisterInfoRequest &req) {
          const auto id = req.get_register_id();
          const auto word_size = debugger.get_domain().get_word_size();

          if (word_size == sizeof(uint64_t)) {
            RegistersX86_64::find_metadata_by_id(id, [&](const auto &md) {
              client.send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              client.send(ErrorResponse(0x45));
            });
          } else if (word_size == sizeof(uint32_t)) {
            RegistersX86_32::find_metadata_by_id(id, [&](const auto &md) {
              client.send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              client.send(ErrorResponse(0x45));
            });
          } else {
            throw std::runtime_error("Unsupported word size!");
          }
        },
        [&](const QueryProcessInfoRequest &req) {
          // TODO
          client.send(QueryProcessInfoResponse(1));
        },
        [&](const QueryMemoryRegionInfoRequest &req) {
          const auto address = req.get_address();

          try {
            const auto start = address & XC_PAGE_MASK;
            const auto size = XC_PAGE_SIZE;
            const auto perms = debugger.get_domain().get_memory_permissions(address);

            client.send(QueryMemoryRegionInfoResponse(start, size, perms));
          } catch (const XenException &e) {
            std::string error(e.what());
            error += std::string(": ") + std::strerror(errno);
            client.send(QueryMemoryRegionInfoErrorResponse(error));
          }
        },
        [&](const QueryCurrentThreadIDRequest &req) {
          // TODO
          client.send(QueryCurrentThreadIDResponse(1));
        },
        [&](const QueryThreadInfoStartRequest &req) {
          client.send(QueryThreadInfoResponse({1}));
        },
        [&](const QueryThreadInfoContinuingRequest &req) {
          client.send(QueryThreadInfoEndResponse());
        },
        [&](const StopReasonRequest &req) {
          client.send(StopReasonSignalResponse(SIGTRAP, 1)); // TODO
        },
        [&](const KillRequest &req) {
          debugger.get_domain().destroy();
          client.send(TerminatedResponse(SIGKILL));
          // TODO
        },
        [&](const SetThreadRequest &req) {
          client.send(OKResponse());
        },
        [&](const RegisterReadRequest &req) {
          const auto id = req.get_register_id();
          const auto thread_id = req.get_thread_id();
          const auto regs = debugger.get_domain().get_cpu_context(thread_id-1);

          std::visit(util::overloaded {
              [&](const auto &regs) {
                regs.find_by_id(id, [&](const auto& md, const auto &reg) {
                  client.send(RegisterReadResponse(reg));
                }, [&]() {
                  client.send(ErrorResponse(0x45)); // TODO
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
                  client.send(ErrorResponse(0x45)); // TODO
                });
              }
          }, regs);
          debugger.get_domain().set_cpu_context(regs);
          client.send(OKResponse());
        },
        [&](const GeneralRegistersBatchReadRequest &req) {
          const auto regs = debugger.get_domain().get_cpu_context();
          std::visit(util::overloaded {
              [&](const RegistersX86_32 &regs) {
                client.send(GeneralRegistersBatchReadResponse(regs));
              },
              [&](const RegistersX86_64 &regs) {
                client.send(GeneralRegistersBatchReadResponse(regs));
              }
          }, regs);
          client.send(NotSupportedResponse());
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
        },
        [&](const MemoryReadRequest &req) {
          const auto address = req.get_address();
          const auto length = req.get_length();

          const auto data = debugger.read_memory_masking_breakpoints(address, length);
          client.send(MemoryReadResponse(data.get(), length));
        },
        [&](const MemoryWriteRequest &req) {
          const auto address = req.get_address();
          const auto length = req.get_length();
          const auto data = req.get_data();

          debugger.write_memory_retaining_breakpoints(
              address, length, (void*)&data[0]);
          client.send(OKResponse());
        },
        [&](const ContinueRequest &req) {
          //client.send(OKResponse());
          debugger.continue_();
          client.send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const ContinueSignalRequest &req) {
          client.send(NotSupportedResponse());
        },
        [&](const StepRequest &req) {
          debugger.single_step();
          client.send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const StepSignalRequest &req) {
          client.send(NotSupportedResponse());
        },
        [&](const BreakpointInsertRequest &req) {
          const auto address = req.get_address();
          debugger.insert_breakpoint(address);
          client.send(OKResponse());
        },
        [&](const BreakpointRemoveRequest &req) {
          const auto address = req.get_address();
          debugger.remove_breakpoint(address);
          client.send(OKResponse());
        },
        [&](const RestartRequest &req) {
          client.send(NotSupportedResponse());
        },
        [&](const DetachRequest &req) {
          // TODO
          client.send(OKResponse());
        },
    };

    std::visit(visitor, packet);

  } catch (const UnknownPacketTypeException &e) {
    std::cout << "[!] Unrecognized packet: ";
    std::cout << e.what() << std::endl;
    client.send(NotSupportedResponse());
  } catch (const XenException &e) {
    std::cout << "[!] XenException:" << std::endl;
    std::cout << e.what() << std::endl;
    client.send(ErrorResponse(0x45));
  }
}
