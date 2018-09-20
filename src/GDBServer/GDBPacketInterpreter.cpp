//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBPacketInterpreter.hpp"
#include "GDBResponsePacket.hpp"
#include "../Registers/RegistersX86.hpp"
#include "../Xen/XenException.hpp"
#include "GDBServer.hpp"

using xd::reg::RegistersX86;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::XenException;

void xd::gdbsrv::interpret_packet(xd::dbg::DebugSessionPV &dbg, const pkt::GDBRequestPacket &packet,
                      std::function<void(const pkt::GDBResponsePacket&)> send)
{
  using namespace xd::gdbsrv::pkt;

  try {
    const auto visitor = util::overloaded {
        [](const StartNoAckModeRequest &req) {
          // do nothing ... handled by GDBServer already
          // TOOD: this is a bit weird, should probably pass some interface to the GDBServer
        },
        [&](const QuerySupportedRequest &req) {
          send(QuerySupportedResponse({
            "PacketSize=20000",
            "QStartNoAckMode+",
            "QThreadSuffixSupported+",
            "QListThreadsInStopReplySupported+",
          }));
        },
        [&](const QueryThreadSuffixSupportedRequest &req) {
          send(OKResponse());
        },
        [&](const QueryListThreadsInStopReplySupportedRequest &req) {
          send(OKResponse());
        },
        [&](const QueryHostInfoRequest &req) {
          const auto domain = dbg.get_domain();
          const auto name = domain.get_name();
          const auto word_size = domain.get_word_size();
          send(QueryHostInfoResponse(word_size, name));
        },
        [&](const QueryRegisterInfoRequest &req) {
          const auto id = req.get_register_id();
          const auto word_size = dbg.get_domain().get_word_size();

          if (word_size == sizeof(uint64_t)) {
            RegistersX86_64::find_metadata_by_id(id, [&](const auto &md) {
              send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              send(ErrorResponse(0x45));
            });
          } else if (word_size == sizeof(uint32_t)) {
            RegistersX86_32::find_metadata_by_id(id, [&](const auto &md) {
              send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              send(ErrorResponse(0x45));
            });
          } else {
            throw std::runtime_error("Unsupported word size!");
          }
        },
        [&](const QueryProcessInfoRequest &req) {
          // TODO
          send(QueryProcessInfoResponse(1));
        },
        [&](const QueryMemoryRegionInfoRequest &req) {
          const auto address = req.get_address();

          try {
            const auto start = address & XC_PAGE_MASK;
            const auto size = XC_PAGE_SIZE;
            const auto perms = dbg.get_domain().get_memory_permissions(address);

            send(QueryMemoryRegionInfoResponse(start, size, perms));
          } catch (const XenException &e) {
            std::string error(e.what());
            error += std::string(": ") + std::strerror(errno);
            send(QueryMemoryRegionInfoErrorResponse(error));
          }
        },
        [&](const QueryCurrentThreadIDRequest &req) {
          // TODO
          send(QueryCurrentThreadIDResponse(1));
        },
        [&](const QueryThreadInfoStartRequest &req) {
          send(QueryThreadInfoResponse({1}));
        },
        [&](const QueryThreadInfoContinuingRequest &req) {
          send(QueryThreadInfoEndResponse());
        },
        [&](const StopReasonRequest &req) {
          send(StopReasonSignalResponse(SIGTRAP, 1)); // TODO
        },
        [dbg, &running](const KillRequest &req) {
          dbg.get_domain().destroy();
          send(TerminatedResponse(SIGKILL));
          running = false;
        },
        [&](const SetThreadRequest &req) {
          send(OKResponse());
        },
        [&](const RegisterReadRequest &req) {
          const auto id = req.get_register_id();
          const auto thread_id = req.get_thread_id();
          const auto regs = dbg.get_domain().get_cpu_context(thread_id-1);

          std::visit(util::overloaded {
              [&](const auto &regs) {
                regs.find_by_id(id, [&](const auto& md, const auto &reg) {
                  send(RegisterReadResponse(reg));
                }, [&]() {
                  send(ErrorResponse(0x45)); // TODO
                });
              }
          }, regs);
        },
        [&](const RegisterWriteRequest &req) {
          const auto id = req.get_register_id();
          const auto value = req.get_value();

          auto regs = dbg.get_domain().get_cpu_context();
          std::visit(util::overloaded {
              [&](auto &regs) {
                regs.find_by_id(id, [&value](const auto&, auto &reg) {
                  reg = value;
                }, [&]() {
                  send(ErrorResponse(0x45)); // TODO
                });
              }
          }, regs);
          dbg.get_domain().set_cpu_context(regs);
          send(OKResponse());
        },
        [&](const GeneralRegistersBatchReadRequest &req) {
          const auto regs = dbg.get_domain().get_cpu_context();
          std::visit(util::overloaded {
              [&](const RegistersX86_32 &regs) {
                send(GeneralRegistersBatchReadResponse(regs));
              },
              [&](const RegistersX86_64 &regs) {
                send(GeneralRegistersBatchReadResponse(regs));
              }
          }, regs);
          send(NotSupportedResponse());
        },
        [&](const GeneralRegistersBatchWriteRequest &req) {
          auto orig_regs_any = dbg.get_domain().get_cpu_context();
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

          const auto data = dbg.read_memory_masking_breakpoints(address, length);
          send(MemoryReadResponse(data.get(), length));
        },
        [&](const MemoryWriteRequest &req) {
          const auto address = req.get_address();
          const auto length = req.get_length();
          const auto data = req.get_data();

          dbg.write_memory_retaining_breakpoints(
              address, length, (void*)&data[0]);
          send(OKResponse());
        },
        [&](const ContinueRequest &req) {
          send(OKResponse());
          dbg.continue_();
          send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const ContinueSignalRequest &req) {
          send(NotSupportedResponse());
        },
        [&](const StepRequest &req) {
          dbg.single_step();
          send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const StepSignalRequest &req) {
          send(NotSupportedResponse());
        },
        [&](const BreakpointInsertRequest &req) {
          const auto address = req.get_address();
          dbg.insert_breakpoint(address);
          send(OKResponse());
        },
        [&](const BreakpointRemoveRequest &req) {
          const auto address = req.get_address();
          dbg.remove_breakpoint(address);
          send(OKResponse());
        },
        [&](const RestartRequest &req) {
          send(NotSupportedResponse());
        },
        [&](const DetachRequest &req) {
          // TODO
          send(OKResponse());
        },
    };

    std::visit(visitor, packet);

  } catch (const UnknownPacketTypeException &e) {
    std::cout << "[!] Unrecognized packet: ";
    std::cout << e.what() << std::endl;
    send(NotSupportedResponse());
  } catch (const XenException &e) {
    std::cout << "[!] XenException:" << std::endl;
    std::cout << e.what() << std::endl;
    send(ErrorResponse(0x45));
  }
}
