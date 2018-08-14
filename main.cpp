#include "REPL/REPL.hpp"
#include "Xen/Domain.hpp"
#include "Xen/Xenctrl.hpp"
#include "Xen/Xenstore.hpp"
#include "Xen/XenForeignMemory.hpp"

#include <sys/mman.h>

using xd::xen::DomID;
using xd::xen::Domain;
using xd::xen::Xenctrl;
using xd::xen::XenForeignMemory;
using xd::xen::Xenstore;

int main() {
  Xenctrl xenctrl;
  XenForeignMemory xen_foreign_memory;
  Xenstore xenstore;

  DomID domid = 1;
  Domain domain(xenctrl, xenstore, xen_foreign_memory, domid);
  domain.pause();
  domain.set_debugging(true);
  domain.map_memory((void*)0x0, 1024, PROT_READ);
  domain.unpause();

  repl::set_prompt("> ");
  repl::do_repl();
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
