/*
#include <iostream>

#include "Registers/RegistersX86_64.hpp"

template <typename T>
struct X;

int main() {
  using namespace reg::x86_64;

  RegistersX86_64 regs;
  regs.get<rip>().set64(0xfeedbead00000000);
  regs.get<rip>().set32(0xdead0000);
  regs.get<rip>().set16(0xbe00);
  regs.get<rip>().set8l(0xef);

  std::cout << std::showbase << std::hex;

  std::cout << "REG\tOFFSET\tVALUE" << std::endl;
  regs.for_each([](const auto &md, auto &reg) {
    std::cout << md.name << "\t" << md.offset << "\t" << reg << std::endl;
  });
}
*/

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "Debugger/Debugger.hpp"
#include "Debugger/GDBStub/GDBStub.hpp"
//#include "Debugger/DebuggerREPL.hpp"
#include "Parser/Parser.hpp"
#include "REPL/Command/MakeCommand.hpp"
#include "REPL/Command/Argument.hpp"
#include "REPL/Command/Flag.hpp"
#include "REPL/Command/Verb.hpp"
#include "REPL/Command/Verb.hpp"
#include "Util/IndentHelper.hpp"
#include "Xen/XenStore.hpp"

using xd::dbg::Debugger;
//using xd::dbg::DebuggerREPL;
using xd::dbg::gdbstub::GDBStub;
using xd::repl::cmd::make_command;
using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::Verb;
using xd::util::IndentHelper;
using xd::xen::XenStore;

std::string stringify_args(int argc, char **argv) {
  const std::vector<std::string> args(argv, argv + argc);

  std::stringstream ss;
  std::for_each(args.begin(), args.end(), [&ss](const std::string &s) {
    ss << s << " ";
  });

  return ss.str();
}

int main(int argc, char **argv) {

  assert(argc == 3);
  std::string name(argv[2]);

  Debugger dbg;
  XenStore xenstore;
  const auto id = xenstore.get_domid_from_name(name);
  dbg.attach(id);

  std::cout << "Attached to guest #" << id << std::endl;

  GDBStub stub(std::stoi(argv[1]));
  stub.run(dbg);
}

  /*
  const auto cmdline_str = stringify_args(argc, argv);

  const auto cmdline_cmd = make_command(Verb(argv[0], "",
    {}, {},
    [](const auto &flags, const auto &args) {
      return []() {
        return;
      };
    }));

  try {
    const auto cmdline_action = cmdline_cmd->match(
        cmdline_str.begin(), cmdline_str.end());
    cmdline_action.value()();
  } catch (const std::runtime_error &e) {
    auto indent = IndentHelper();
    std::cerr << e.what() << std::endl;
    cmdline_cmd->print(std::cerr, indent);
    exit(1);
  }

  DebuggerREPL dbg_repl;
  dbg_repl.run();

}
  */

/*
#include <cassert>
#include <cctype>
#include <iostream>

#include "REPL/Command/Command.hpp"

using xd::repl::cmd::Command;
using xd::repl::cmd::Verb;
using xd::repl::cmd::Flag;
using xd::repl::cmd::Argument;

int main() {
  const auto match_number = [](auto begin, auto end) {
    return std::find_if_not(begin, end, [](char c) {
      return std::isdigit(static_cast<unsigned char>(c));
    });
  };

  auto brk = Command("break", "Manage breakpoints.", {
    Verb("create", "Create a breakpoint.",
      {}, {},
      [](auto& flags, auto& args) {
        return []() {
          std::cout << "Breakpoint created." << std::endl;
        };
    }),
    Verb("delete", "Delete a breakpoint.",
      {
        Flag('f', "force", "Force deletion.", {}),
        Flag('v', "value", "A flag with a value.", {
          Argument("value", "A value.", match_number)
        })
      },
      {
        Argument("id", "ID of the breakpoint to delete.", match_number)
      },
      [](auto& flags, auto& args) {
        const auto get_number = [](const auto& s) {
          return std::stoi(s, 0, 0);
        };

        int id = args.template get<int>("id", get_number);
        bool force = flags.has("force");
        auto value_flag = flags.get("value");
        int val = -1;
        if (value_flag) {
          val = value_flag.value().template get<int>("value", get_number);
        }

        return [id, force, val]() {
          std::cout << "Breakpoint " << id << " deleted." << std::endl;
          std::cout << "force: " << force << std::endl;
          std::cout << "value: " << val << std::endl;
        };
  })});

  std::string s = "";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s));
  s = "asdf";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s));
  s = "asdf hjkl";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s));
  s = "break";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s));
  s = "break create";
  std::cout << "s: " << s << std::endl;
  assert(!!brk.match(s));
  //s = "break delete";
  //std::cout << "s: " << s << std::endl;
  //assert(!brk.match(s.begin(), s.end()));
  s = "break delete  -f -v 34 12";
  std::cout << "s: " << s << std::endl;
  assert(!!brk.match(s));
  auto act = brk.match(s);
  if (act) {
    act.value()();
  }
  //s = "break delete 12 12";
  //std::cout << "s: " << s << std::endl;
  //assert(!brk.match(s.begin(), s.end()));

}
*/

/*
#include "REPL/REPL.hpp"

int main() {
  repl::set_prompt("> ");
  repl::start();
}
*/

/*
#include "Xen/Domain.hpp"
#include "Xen/PrivCmd.hpp"
#include "Xen/Registers.hpp"
#include "Xen/XenException.hpp"
#include "Xen/XenContext.hpp"
#include "Xen/XenCtrl.hpp"
#include "Xen/XenStore.hpp"
#include "Xen/XenForeignMemory.hpp"

#include <iostream>
#include <sys/mman.h>

using xd::xen::DomID;
using xd::xen::Domain;
using xd::xen::PrivCmd;
using xd::xen::Registers64;
using xd::xen::XenContext;
using xd::xen::XenCtrl;
using xd::xen::XenException;
using xd::xen::XenForeignMemory;
using xd::xen::XenStore;

int main(int argc, char** argv) {
  XenContext context;

  DomID domid = std::stoul(argv[1]);
  Domain domain(context, domid);

  int buf_len = 0x1000;
  void* buf = malloc(buf_len);

  domain.hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [buf, buf_len](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = 0xfeeb8;
    memio.uva = (uint64_aligned_t)((unsigned long)buf);
    memio.len = buf_len;
    memio.gwr = 0;

    if (mlock(buf, buf_len))
      throw XenException("mlock failed!");
  }, [buf, buf_len]() {
    munlock(buf, buf_len);
  });

  for (unsigned long i = 0; i < buf_len/sizeof(uint64_t); ++i) {
    printf("%.016lx\n", *((uint64_t*)buf+i));
  }
}
*/

/*
#include <iostream>
#include "Parser/ParserException.hpp"
#include "Parser/Parser.hpp"

using xd::parser::Parser;

using xd::parser::except::ParserException;
using xd::parser::except::ExpectWrongTokenException;
using xd::parser::except::ExpectMissingTokenException;
using xd::parser::except::ExtraTokenException;
using xd::parser::except::MissingExpressionException;
using xd::parser::except::SentinelMergeException;
using xd::parser::except::InvalidInputException;

void print_parser_exception(const ParserException& e) {
  std::cerr << e.input() << std::endl;
  std::cerr << std::string(e.pos(), ' ') << "^" << std::endl;
}

int main() {
  Parser parser;
  try {
    auto expr = parser.parse("0x1101");
  } catch (const ExpectMissingTokenException &e) {
    std::cerr << e.msg() << std::endl;
    print_parser_exception(e);
  } catch (const ExpectWrongTokenException &e) {
    std::cerr << e.msg() << std::endl;
    print_parser_exception(e);
  } catch (const ExtraTokenException &e) {
    std::cerr << "Extra token!" << std::endl;
    print_parser_exception(e);
  } catch (const MissingExpressionException &e) {
    std::cerr << "Expected expression!" << std::endl;
    print_parser_exception(e);
  } catch (const SentinelMergeException &e) {
    std::cerr << "You merged a sentinel!? Logically, this should never happen..." << std::endl;
  } catch (const InvalidInputException &e) {
    std::cerr << "Invalid input!" << std::endl;
    print_parser_exception(e);
  }

  return 0;
}
*/
