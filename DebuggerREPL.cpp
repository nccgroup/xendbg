//
// Created by Spencer Michaels on 8/28/18.
//

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

using xd::DebuggerREPL;

DebuggerREPL::DebuggerREPL() {
  setup_repl();
}

void DebuggerREPL::run() {
  _repl.run();
}

void DebuggerREPL::setup_repl() {
  _repl.set_prompt_configurator([this]() {
    std::string prompt = "> ";

    auto& domain = _debugger.get_current_domain();
    if (domain)
      prompt = "xen:" + std::to_string(domain.value().get_domid()) + " " + prompt;
    return prompt;
  });

  _repl.add_command(make_command("guest", "Manage guests.", {

    Verb("list", "List all guests and their respective states.",
      {}, {},
      [](auto &/*flags*/, auto &/*args*/) {
        return [](auto&) {
          // _debugger.get_all_domains();
        };
      }),

    Verb("attach", "Attach to a guest.",
      {},
      {
        Argument("domid/name", "The domID or name of a guest to attach to.",
            next_whitespace)
      },
      [this](auto &/*flags*/, auto &args) {

        auto domid_or_name = args.get("domid/name");

        xen::DomID domid;
        try {
          domid = (xen::DomID)std::stoul(domid_or_name);
        } catch (std::invalid_argument& e) {
          domid = _debugger.get_xen_handle().get_xenstore()
              .get_domid_from_name(domid_or_name);
        }

        return [this, domid](auto&) {
          _debugger.attach(domid); // TODO
        };
      }),

    Verb("attach", "Detach from a guest.",
      {}, {},
      [this](auto &flags, auto &args) {
        return [this](auto&) {
          _debugger.detach();
        };
      }),
  }));
}
