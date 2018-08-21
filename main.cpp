#include <cassert>
#include <cctype>
#include <iostream>

#include "REPL/Command/Command.hpp"

using xd::repl::cmd::Command;
using xd::repl::cmd::Verb;
using xd::repl::cmd::Flag;
using xd::repl::cmd::Argument;

int main() {
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
        Flag('f', "force", "Force deletion.", {})
      },
      {
        Argument("id", "ID of the breakpoint to delete.", [](auto begin, auto end) {
          return std::find_if_not(begin, end, [](char c) {
            return std::isdigit(static_cast<unsigned char>(c));
          });
        })
      },
      [](auto& flags, auto& args) {
        bool force = flags.has("force");
        int id = args.template get<int>("id", [](const auto& s) {
          return std::stoi(s, 0, 0);
        });
        return [id, force]() {
          std::cout << "Breakpoint " << id << " deleted." << std::endl;
          std::cout << "forced: " << force << std::endl;
        };
  })});

  std::string s = "";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s.begin(), s.end()));
  s = "asdf";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s.begin(), s.end()));
  s = "asdf hjkl";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s.begin(), s.end()));
  s = "break";
  std::cout << "s: " << s << std::endl;
  assert(!brk.match(s.begin(), s.end()));
  s = "break create";
  std::cout << "s: " << s << std::endl;
  assert(!!brk.match(s.begin(), s.end()));
  //s = "break delete";
  //std::cout << "s: " << s << std::endl;
  //assert(!brk.match(s.begin(), s.end()));
  s = "break delete -f 12";
  std::cout << "s: " << s << std::endl;
  assert(!!brk.match(s.begin(), s.end()));
  auto act = brk.match(s.begin(), s.end());
  if (act) {
    act.value()();
  }
  //s = "break delete 12 12";
  //std::cout << "s: " << s << std::endl;
  //assert(!brk.match(s.begin(), s.end()));

}

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
    auto expr = parser.parse("(($rip-&main) + 0x40) + (*$esp)");
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
