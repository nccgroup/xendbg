//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>

#include "DebuggerREPL.hpp"
#include "REPL/Command/Argument.hpp"
#include "REPL/Command/Flag.hpp"
#include "REPL/Command/MakeCommand.hpp"
#include "REPL/Command/Verb.hpp"
#include "Util/string.hpp"

using xd::Debugger;
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

void DebuggerREPL::run() {
  _repl.run();
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
  _repl.add_command(make_command("domain", "Manage domains.", {
    Verb("list", "List all guests and their respective states.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto domains = _debugger.get_all_domains();
          for (const auto &domain : domains) {
            // TODO: formatting
            std::cout << domain.get_domid() << "\t" << domain.get_name() << std::endl;
          }
        };
      }),

    Verb("attach", "Attach to a domain.",
      {},
      {
        Argument("domid/name", "Either the numeric domID or the name of a domain to attach to.",
            match_optionally_quoted_string)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto domid_or_name = args.get("domid/name");

        xen::DomID domid;
        try {
          domid = (xen::DomID)std::stoul(domid_or_name);
        } catch (std::invalid_argument& e) {
          // TODO: this can throw an exception too
          domid = _debugger.get_xen_handle().get_xenstore()
              .get_domid_from_name(domid_or_name);
        }

        return [this, domid]() {
          _debugger.attach(domid);

          const auto domain = _debugger.get_current_domain().value();
          std::cout << "Attached to domain " << domain.get_domid() << " (" << domain.get_name() << ")." << std::endl;
        };
      }),

    Verb("detach", "Detach from the current domain.",
      {}, {},
      [this](auto &flags, auto &args) {
        return [this]() {
          // TODO: handle not being attached yet
          _debugger.detach();
        };
      }),
  }));

  /**
   *
   */
  _repl.add_command(make_command("info", "Query the state of Xen, the attached guest and its registers.", {
      Verb("domain", "Query the state of the current domain.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            // TODO: handle not being attached yet
            const auto domain = _debugger.get_current_domain();
            // TODO: actually print things
          };
        }),
      Verb("registers", "Query the register state of the current domain.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            // TODO
          };
        }),
      Verb("xen", "Query Xen version and capabilities.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            // TODO
          };
        }),
  }));
}
