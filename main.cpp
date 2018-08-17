/*
#include "REPL/REPL.hpp"

int main() {
  repl::set_prompt("> ");
  repl::start();
}
*/

#include "Xen/Domain.hpp"
#include "Xen/Registers.hpp"
#include "Xen/XenException.hpp"
#include "Xen/XenCtrl.hpp"
#include "Xen/XenStore.hpp"
#include "Xen/XenForeignMemory.hpp"

#include <iostream>
#include <sys/mman.h>

using xd::xen::DomID;
using xd::xen::Domain;
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
  try {

    auto regs = std::get<Registers64>(xenctrl.get_cpu_context(domain));
    {
      printf("mapping memory at rip: %p\n", regs.rip);
      auto mem = domain.map_memory(regs.rip, XC_PAGE_SIZE, PROT_READ | PROT_WRITE);
      auto p = (uint64_t*)mem.get();
      printf("0x%.06lx: %.016lx\n", regs.rip, *p);
      *((uint8_t*)p) = 0x9090;
    }

    //domain.set_debugging(true);
    /*
    for (uint64_t addr = XC_PAGE_SIZE;; addr += XC_PAGE_SIZE) {
      auto mem = domain.map_memory(addr, XC_PAGE_SIZE, PROT_READ);
      printf("mapped page %p\n", addr);
      auto p = (uint64_t*)mem.get();
      for (uint64_t i = 0; i < XC_PAGE_SIZE/sizeof(uint64_t); ++i) {
        printf("0x%.06lx: %.016lx\n", addr + i*sizeof(uint64_t), *p);
        ++p;
      }
    }
    */
  } catch (const XenException& e) {
    std::cerr << e.what() << std::endl;
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
