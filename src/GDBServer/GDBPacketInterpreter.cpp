//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBPacketInterpreter.hpp"
#include "GDBResponsePacket.hpp"
#include "../Registers/RegistersX86.hpp"
#include "../Xen/XenException.hpp"
#include "../Debugger/DebugSessionPV.hpp"
#include "GDBServer.hpp"

using xd::dbg::DebugSessionPV;
using xd::gdbsrv::GDBPacketInterpreter;
using xd::reg::RegistersX86;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::XenException;

GDBPacketInterpreter::GDBPacketInterpreter(GDBServer &server, DebugSessionPV &debugger)
  : _server(server), _debugger(debugger)
{
}

void GDBPacketInterpreter::interpret(const pkt::GDBRequestPacket &packet) {
  using namespace xd::gdbsrv::pkt;
  try {
    const auto visitor = util::overloaded {
        [&](const StartNoAckModeRequest &req) {
          // do nothing ... handled by GDBServer already
          // TOOD: this is a bit weird, should probably pass some interface to the GDBServer
        },
        [&](const QuerySupportedRequest &req) {
          _server.send(QuerySupportedResponse({
            "PacketSize=20000",
            "QStartNoAckMode+",
            "QThreadSuffixSupported+",
            "QListThreadsInStopReplySupported+",
          }));
        },
        [&](const QueryThreadSuffixSupportedRequest &req) {
          _server.send(OKResponse());
        },
        [&](const QueryListThreadsInStopReplySupportedRequest &req) {
          _server.send(OKResponse());
        },
        [&](const QueryHostInfoRequest &req) {
          const auto domain = _debugger.get_domain();
          const auto name = domain.get_name();
          const auto word_size = domain.get_word_size();
          _server.send(QueryHostInfoResponse(word_size, name));
        },
        [&](const QueryRegisterInfoRequest &req) {
          const auto id = req.get_register_id();
          const auto word_size = _debugger.get_domain().get_word_size();

          if (word_size == sizeof(uint64_t)) {
            RegistersX86_64::find_metadata_by_id(id, [&](const auto &md) {
              _server.send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              _server.send(ErrorResponse(0x45));
            });
          } else if (word_size == sizeof(uint32_t)) {
            RegistersX86_32::find_metadata_by_id(id, [&](const auto &md) {
              _server.send(QueryRegisterInfoResponse(
                  md.name, 8*md.width, md.offset, md.gcc_id));
            }, [&]() {
              _server.send(ErrorResponse(0x45));
            });
          } else {
            throw std::runtime_error("Unsupported word size!");
          }
        },
        [&](const QueryProcessInfoRequest &req) {
          // TODO
          _server.send(QueryProcessInfoResponse(1));
        },
        [&](const QueryMemoryRegionInfoRequest &req) {
          const auto address = req.get_address();

          try {
            const auto start = address & XC_PAGE_MASK;
            const auto size = XC_PAGE_SIZE;
            const auto perms = _debugger.get_domain().get_memory_permissions(address);

            _server.send(QueryMemoryRegionInfoResponse(start, size, perms));
          } catch (const XenException &e) {
            std::string error(e.what());
            error += std::string(": ") + std::strerror(errno);
            _server.send(QueryMemoryRegionInfoErrorResponse(error));
          }
        },
        [&](const QueryCurrentThreadIDRequest &req) {
          // TODO
          _server.send(QueryCurrentThreadIDResponse(1));
        },
        [&](const QueryThreadInfoStartRequest &req) {
          _server.send(QueryThreadInfoResponse({1}));
        },
        [&](const QueryThreadInfoContinuingRequest &req) {
          _server.send(QueryThreadInfoEndResponse());
        },
        [&](const StopReasonRequest &req) {
          _server.send(StopReasonSignalResponse(SIGTRAP, 1)); // TODO
        },
        [&](const KillRequest &req) {
          _debugger.get_domain().destroy();
          _server.send(TerminatedResponse(SIGKILL));
          // TODO
        },
        [&](const SetThreadRequest &req) {
          _server.send(OKResponse());
        },
        [&](const RegisterReadRequest &req) {
          const auto id = req.get_register_id();
          const auto thread_id = req.get_thread_id();
          const auto regs = _debugger.get_domain().get_cpu_context(thread_id-1);

          std::visit(util::overloaded {
              [&](const auto &regs) {
                regs.find_by_id(id, [&](const auto& md, const auto &reg) {
                  _server.send(RegisterReadResponse(reg));
                }, [&]() {
                  _server.send(ErrorResponse(0x45)); // TODO
                });
              }
          }, regs);
        },
        [&](const RegisterWriteRequest &req) {
          const auto id = req.get_register_id();
          const auto value = req.get_value();

          auto regs = _debugger.get_domain().get_cpu_context();
          std::visit(util::overloaded {
              [&](auto &regs) {
                regs.find_by_id(id, [&value](const auto&, auto &reg) {
                  reg = value;
                }, [&]() {
                  _server.send(ErrorResponse(0x45)); // TODO
                });
              }
          }, regs);
          _debugger.get_domain().set_cpu_context(regs);
          _server.send(OKResponse());
        },
        [&](const GeneralRegistersBatchReadRequest &req) {
          const auto regs = _debugger.get_domain().get_cpu_context();
          std::visit(util::overloaded {
              [&](const RegistersX86_32 &regs) {
                _server.send(GeneralRegistersBatchReadResponse(regs));
              },
              [&](const RegistersX86_64 &regs) {
                _server.send(GeneralRegistersBatchReadResponse(regs));
              }
          }, regs);
          _server.send(NotSupportedResponse());
        },
        [&](const GeneralRegistersBatchWriteRequest &req) {
          auto orig_regs_any = _debugger.get_domain().get_cpu_context();
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

          const auto data = _debugger.read_memory_masking_breakpoints(address, length);
          _server.send(MemoryReadResponse(data.get(), length));
        },
        [&](const MemoryWriteRequest &req) {
          const auto address = req.get_address();
          const auto length = req.get_length();
          const auto data = req.get_data();

          _debugger.write_memory_retaining_breakpoints(
              address, length, (void*)&data[0]);
          _server.send(OKResponse());
        },
        [&](const ContinueRequest &req) {
          _server.send(OKResponse());
          _debugger.continue_();
          _server.send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const ContinueSignalRequest &req) {
          _server.send(NotSupportedResponse());
        },
        [&](const StepRequest &req) {
          _debugger.single_step();
          _server.send(StopReasonSignalResponse(SIGTRAP, 1));
        },
        [&](const StepSignalRequest &req) {
          _server.send(NotSupportedResponse());
        },
        [&](const BreakpointInsertRequest &req) {
          const auto address = req.get_address();
          _debugger.insert_breakpoint(address);
          _server.send(OKResponse());
        },
        [&](const BreakpointRemoveRequest &req) {
          const auto address = req.get_address();
          _debugger.remove_breakpoint(address);
          _server.send(OKResponse());
        },
        [&](const RestartRequest &req) {
          _server.send(NotSupportedResponse());
        },
        [&](const DetachRequest &req) {
          // TODO
          _server.send(OKResponse());
        },
    };

    std::visit(visitor, packet);

  } catch (const UnknownPacketTypeException &e) {
    std::cout << "[!] Unrecognized packet: ";
    std::cout << e.what() << std::endl;
    _server.send(NotSupportedResponse());
  } catch (const XenException &e) {
    std::cout << "[!] XenException:" << std::endl;
    std::cout << e.what() << std::endl;
    _server.send(ErrorResponse(0x45));
  }
}
