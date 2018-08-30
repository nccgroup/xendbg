//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>

#include "DebuggerREPL.hpp"
#include "Parser/Parser.hpp"
#include "REPL/Command/Argument.hpp"
#include "REPL/Command/Flag.hpp"
#include "REPL/Command/MakeCommand.hpp"
#include "REPL/Command/MatchHelper.hpp"
#include "REPL/Command/Verb.hpp"
#include "Util/string.hpp"

using xd::Debugger;
using xd::parser::Parser;
using xd::parser::expr::Constant;
using xd::parser::expr::Expression;
using xd::parser::expr::Label;
using xd::parser::expr::Variable;
using xd::parser::expr::op::Dereference;
using xd::parser::expr::op::Negate;
using xd::parser::expr::op::Equals;
using xd::parser::expr::op::Add;
using xd::parser::expr::op::Subtract;
using xd::parser::expr::op::Multiply;
using xd::parser::expr::op::Divide;
using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::make_command;
using xd::repl::cmd::Verb;
using xd::repl::cmd::match::match_everything;
using xd::util::string::next_whitespace;
using xd::util::string::match_optionally_quoted_string;

using xd::DebuggerREPL;

DebuggerREPL::DebuggerREPL() {
  setup_repl();
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
  /*
  _repl.set_no_match_handler([this](const std::string &line) {
    parse_and_eval_expression(line);
  });
  */

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
      Verb("variables", "Query variables.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            const auto& vars = _debugger.get_vars();
            for (const auto& var : vars) {
              std::cout << var.first << "\t" << var.second << std::endl;
            }
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

  /**
   * print <expr>
   */
  _repl.add_command(make_command(
      Verb("print", "Display the value of an expression.",
        {},
        {
          Argument("expr", "The expression to display.", match_everything),
        },
        [this](auto &/*flags*/, auto &args) {
          const auto expr_str = args.get("expr");
          return [this, expr_str]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);
            const auto result = evaluate_expression(expr, false);
            std::cout << result << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("set", "Write to a variable, register, or memory region.",
        {},
        {
          Argument("$var = expr...", "", match_everything),
        },
        [this](auto &/*flags*/, auto &args) {
          const auto expr_str = args.get("$var = expr...");
          return [this, expr_str]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);

            // Make sure the expr is of the form $var = expr
            const bool is_var_equals_expr =
              expr.is_binex() && expr.as_binex().x.template is_of_type<Variable>();

            if (!is_var_equals_expr)
              throw std::runtime_error("Input must be of the form $var = expr...");

            const auto result = evaluate_expression(expr, true);
            std::cout << result << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("unset", "Unset a variable.",
        {},
        {
          Argument("$var", "", match_everything),
        },
        [this](auto &/*flags*/, auto &args) {
          const auto expr_str = args.get("$var");
          return [this, expr_str]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);

            // Make sure the expr is of the form $var
            if (!expr.template is_of_type<Variable>())
              throw std::runtime_error("Not a variable!");

            const auto name = expr.template as<Variable>().value;
            _debugger.delete_var(name);
          };
        })));
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
  std::cout << std::hex << std::showbase;

  std::visit(util::overloaded {
    [](const xen::Registers32 regs) {
      regs.for_each([](const auto &name, auto val) {
        std::cout << name << "\t" << val << std::endl;
      });
    },
    [](const xen::Registers64 regs) {
      regs.for_each([](const auto &name, auto val) {
        std::cout << name << "\t" << val << std::endl;
      });
    }
  }, regs);
}

void DebuggerREPL::print_xen_info(const xen::XenHandle &xen) {
  auto version = xen.get_xenctrl().get_xen_version();
  std::cout << "Xen " << version.major << "." << version.minor << std::endl;
}

uint64_t DebuggerREPL::evaluate_expression(const Expression& expr, bool allow_write) {
  return expr.visit<uint64_t>(util::overloaded {
    [](const Constant& ex) {
      return ex.value;
    },
    [](const Label& ex) {
      return 0UL;
    },
    [this](const Variable& ex) {
      return _debugger.get_var(ex.value);
    },
    [this, allow_write](const Expression::UnaryExpressionPtr& ex) {
      const auto& op = ex->op;
      const auto& x_value = evaluate_expression(ex->x, allow_write);

      return std::visit(util::overloaded {
          [](Dereference) {
            return 0UL;
          },
          [x_value](Negate) {
            return -x_value;
          },
      }, op);

      return 0UL;
    },
    [this, allow_write](const Expression::BinaryExpressionPtr& ex) {
      const auto& op = ex->op;
      const auto get_xy = [this, allow_write, &ex]() {
        return std::make_pair(
            evaluate_expression(ex->x, allow_write),
            evaluate_expression(ex->y, allow_write));
      };

      return std::visit(util::overloaded {
        [this, allow_write, &ex](Equals) {
          if (!allow_write)
            // TODO
            throw std::runtime_error("Use 'set' to modify variables.");

          if (ex->x.is_of_type<Variable>()) {
            const auto &var = ex->x.as<Variable>().value;
            const auto val = evaluate_expression(ex->y, allow_write);
            _debugger.set_var(var, val); 
            return val;
          }
          return 0UL;
        },
        [get_xy](Add) {
          const auto [x, y] = get_xy();
          return x + y;
        },
        [get_xy](Subtract) {
          const auto [x, y] = get_xy();
          return x - y;
        },
        [get_xy](Multiply) {
          const auto [x, y] = get_xy();
          return x * y;
        },
        [get_xy](Divide) {
          const auto [x, y] = get_xy();
          return x / y;
        },
      }, op);

      return 0UL;
    },
  });
}
