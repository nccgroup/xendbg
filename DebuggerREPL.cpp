//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>

#include "DebuggerREPL.hpp"
#include "Parser/Parser.hpp"
#include "REPL/Command/Argument.hpp"
#include "REPL/Command/Flag.hpp"
#include "REPL/Command/MakeCommand.hpp"
#include "REPL/Command/Verb.hpp"
#include "Util/string.hpp"
#include "ExpressionEvaluator.hpp"

using xd::Debugger;
using xd::parser::Parser;
using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::make_command;
using xd::repl::cmd::Verb;
using xd::util::string::next_whitespace;
using xd::util::string::match_optionally_quoted_string;

using xd::DebuggerREPL;

DebuggerREPL::DebuggerREPL() {
  setup_repl();
}

void DebuggerREPL::parse_and_eval_expression(const std::string &s) {
  Parser parser;
  auto ex = parser.parse(s);
  // TODO: evaluate expression
}

void DebuggerREPL::run() {
  repl::REPL::run(_repl);
}

void DebuggerREPL::setup_repl() {
  /**
   * Display the domID in the prompt if attached to a domain
   */
  _repl.set_prompt_configurator([this]() {
    std::string prompt = "> ";

    auto& domain = _debugger.get_current_domain();
    if (domain)
      prompt = "xen:" + std::to_string(domain.value().get_domid()) + " " + prompt;
    return prompt;
  });

  /**
   * If what is entered isn't a command, interpret it as an expression and evaluate it
   */
   // TODO: Also need an equivalent for completion, e.g. $<tab> completes variables
  _repl.set_no_match_handler([this](const std::string &line) {
    parse_and_eval_expression(line);
  });

  /**
   * Standard commands: help and quit
   */
  _repl.add_command(make_command(
    Verb("help", "Print help.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this](){
          _repl.print_help(std::cout);
        };
      })));
  _repl.add_command(make_command(
    Verb("quit", "Quit.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this](){
          _repl.exit();
        };
      })));

  /**
   * domain
   *    attach <id/name>
   *    detach
   *    list
   */
  _repl.add_command(make_command("guest", "Manage guest domains.", {
    Verb("list", "List all guests and their respective states.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto domains = _debugger.get_guest_domains();
          for (const auto &domain : domains) {
            // TODO: formatting
            std::cout << domain.get_domid() << "\t" << domain.get_name() << std::endl;
          }
        };
      }),

    Verb("attach", "Attach to a domain.",
      {},
      {
        Argument("domid/name", "Either the numeric domID or the name of a guest to attach to.",
            match_optionally_quoted_string)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto domid_or_name = args.get("domid/name");

        xen::DomID domid;
        try {
          domid = (xen::DomID)std::stoul(domid_or_name);
        } catch (std::invalid_argument& e) {
          domid = _debugger.get_xen_handle().get_xenstore()
              .get_domid_from_name(domid_or_name);
        }

        return [this, domid]() {
          _debugger.attach(domid);

          const auto domain = _debugger.get_current_domain().value();
          std::cout << "Attached to guest " << domain.get_domid() << " (" << domain.get_name() << ")." << std::endl;
        };
      }),

    Verb("detach", "Detach from the current domain.",
      {}, {},
      [this](auto &flags, auto &args) {
        return [this]() {
          get_domain_or_fail();
          _debugger.detach();
        };
      }),
  }));

  /**
   *
   */
  _repl.add_command(make_command("info", "Query the state of Xen, the attached guest and its registers.", {
      Verb("guest", "Query the state of the current guest.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            // TODO: handle not being attached yet
            auto domain = get_domain_or_fail();
            print_domain_info(domain);
          };
        }),
      Verb("registers", "Query the register state of the current domain.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            auto domain = get_domain_or_fail();
            auto regs = domain.get_cpu_context(0);

            print_registers(regs);
          };
        }),
      Verb("xen", "Query Xen version and capabilities.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            print_xen_info(_debugger.get_xen_handle());
          };
        }),
  }));
}

xd::xen::Domain &DebuggerREPL::get_domain_or_fail() {
  auto domain = _debugger.get_current_domain();
  if (!domain)
    throw std::runtime_error("No domain!");
  return domain.value();
}

void DebuggerREPL::print_domain_info(const xen::Domain &domain) {
  const auto dominfo = domain.get_info();

  std::cout
    << "Domain " << domain.get_domid() << " (" << domain.get_name() << "):" << std::endl
    << domain.get_word_size() * 8 << "-bit " << (dominfo.hvm ? "HVM" : "PV") << std::endl;
}

void DebuggerREPL::print_registers(const xen::Registers& regs) {
  std::visit(util::overloaded {
    [](const xen::Registers32 regs) {
      regs.for_each([](const auto &name, auto val) {
        std::cout << name << "\t0x" << std::hex << val << std::endl;
      });
    },
    [](const xen::Registers64 regs) {
      regs.for_each([](const auto &name, auto val) {
        std::cout << name << "\t0x" << std::hex << val << std::endl;
      });
    }
  }, regs);
}

void DebuggerREPL::print_xen_info(const xen::XenHandle &xen) {
  auto version = xen.get_xenctrl().get_xen_version();
  std::cout << "Xen " << version.major << "." << version.minor << std::endl;
}
