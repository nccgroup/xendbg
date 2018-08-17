/*
#include "REPL/REPL.hpp"

int main() {
  repl::set_prompt("> ");
  repl::start();
}
*/

#include "Xen/Domain.hpp"
#include "Xen/DomCtl.hpp"
#include "Xen/Registers.hpp"
#include "Xen/XenException.hpp"
#include "Xen/XenCtrl.hpp"
#include "Xen/XenStore.hpp"
#include "Xen/XenForeignMemory.hpp"

#include <iostream>
#include <sys/mman.h>

using xd::xen::DomID;
using xd::xen::Domain;
using xd::xen::DomCtl;
using xd::xen::Registers64;
using xd::xen::XenCtrl;
using xd::xen::XenException;
using xd::xen::XenForeignMemory;
using xd::xen::XenStore;

int main(int argc, char** argv) {
  XenCtrl xenctrl;
  XenForeignMemory xen_foreign_memory;
  XenStore xenstore;

  DomID domid = std::stoul(argv[1]);
  Domain domain(xenctrl, xenstore, xen_foreign_memory, domid);

  int buf_len = 0x1000;
  void* buf = malloc(buf_len);
  DomCtl domctl;

  domctl.do_domctl(domain, XEN_DOMCTL_gdbsx_guestmemio, [buf, buf_len](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = 0xfeeb8;
    memio.uva = (uint64_aligned_t)((unsigned long)buf);
    memio.len = buf_len;
    memio.gwr = 0;
  }, buf, buf_len);

  for (int i = 0; i < buf_len/sizeof(uint64_t); ++i) {
    printf("%lx\n", *((uint64_t*)buf+i));
  }
}

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
