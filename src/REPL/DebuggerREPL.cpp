//
// Created by Spencer Michaels on 8/28/18.
//

#include <iomanip>
#include <iostream>
#include <stdexcept>

#include <elfio/elfio.hpp>

#include <Util/string.hpp>
#include <Xen/XenException.hpp>

#include "DebuggerREPL.hpp"
#include "Parser/Parser.hpp"
#include "Command/Argument.hpp"
#include "Command/Flag.hpp"
#include "Command/MakeCommand.hpp"
#include "Command/Match.hpp"
#include "Command/MatchHelper.hpp"
#include "Command/Verb.hpp"

using xd::dbg::Debugger;
using xd::dbg::DebuggerREPL;
using xd::dbg::InvalidInputException;
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
using xd::repl::NoSuchVariableException;
using xd::repl::cmd::Argument;
using xd::repl::cmd::Flag;
using xd::repl::cmd::make_command;
using xd::repl::cmd::match::make_match_one_of;
using xd::repl::cmd::match::match_everything;
using xd::repl::cmd::match::match_number_unsigned;
using xd::repl::cmd::Verb;
using xd::util::string::next_whitespace;
using xd::util::string::match_optionally_quoted_string;

DebuggerREPL::DebuggerREPL(bool non_stop_mode)
  : _dwrap(repl::DebuggerWrapper(non_stop_mode))
{
  setup_repl();
}

void DebuggerREPL::run() {
  repl::REPL::run(_repl, [](const auto &action) {
    try {
      action();
    } catch (const xen::XenException &e) {
      std::cout << e.what();
      if (e.get_err())
        std::cout << " (" << std::strerror(e.get_err()) << ")";
      std::cout << std::endl;
    } catch (const InvalidInputException &e) {
      std::cout << e.what() << std::endl;
    } catch (const parser::except::ParserException &e) {
      std::cout << "Invalid input! Parse failed at:" << std::endl;
      std::cout << e.input() << std::endl;
      std::cout << std::string(e.pos(), ' ') << "^" << std::endl;
    } catch (const parser::except::ExpectException &e) {
      std::cout << "Invalid input! Parse failed at:" << std::endl;
      std::cout << e.input() << std::endl;
      std::cout << std::string(e.pos(), ' ') << "^" << std::endl;
    } catch (const NoSuchVariableException &e) {
      std::cout << "No such variable: " << e.what() << std::endl;
    } catch (const NoSuchBreakpointException &e) {
      // TODO
      std::cout << "No such breakpoint: #" << e.get_address() << std::endl;
    }
  });
}

void DebuggerREPL::setup_repl() {
  /**
   * Display the domID in the prompt if attached to a domain
   */
  _repl.set_prompt_configurator([this]() {
    std::string prompt = "> ";

    if (_dwrap.get_debugger()) {
      auto s = _dwrap.get_debugger()->get_domain().get_name();
      auto domid = _dwrap.get_debugger()->get_domain().get_domid();
      prompt = std::string(!s.empty() ? s : "dom"+std::to_string(domid)) + " " + prompt;
    }
    return prompt;
  });

  _repl.set_custom_completer([this](const std::string &line) {
    // satisfy type-inference
    std::optional<std::vector<std::string>> ret = std::nullopt;

    const auto last_ws_pos = next_whitespace(line.rbegin(), line.rend());
    if (last_ws_pos == line.rend())
      return ret;

    if (*(last_ws_pos-1) == '&') {
      const auto symbol_map = _dwrap.get_symbols();
      std::vector<std::string> options;
      std::transform(symbol_map.begin(), symbol_map.end(), std::back_inserter(options),
        [](const auto &pair) {
          return std::string("&") + pair.first;
        });
      ret = std::move(options);
    }
    return ret;
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
          /*
          const auto domains = _debugger.get_guest_domains();
          for (const auto &domain : domains) {
            // TODO: formatting
            std::cout << domain.get_name() << "\t" << domain.get_domid() << std::endl;
          }
           */
        };
      }),

    Verb("attach", "Attach to a domain.",
      {},
      {
        Argument("domid/name",
            "Either the numeric domID or the name of a guest to attach to.", 
            match_optionally_quoted_string<std::string::const_iterator>,
              [this](const auto&, const auto&) {
                std::vector<std::string> options;
                /*
                const auto domains = _debugger.get_guest_domains();
                std::transform(domains.begin(), domains.end(),
                  std::back_inserter(options), [](const auto& domain) {
                    return domain.get_name();
                  });
                  */
                return options;
              }),
      },
      [this](auto &/*flags*/, auto &args) {
        const auto domid_or_name = args.get("domid/name");

        return [this, domid_or_name]() {
          xen::DomID domid;
          try {
            domid = (xen::DomID)std::stoul(domid_or_name);
          } catch (std::invalid_argument& e) {
            //domid = _dwrap.get_xen_handle().xenstore.get_domid_from_name(domid_or_name);
            domid = -1; // TODO
          }

          const auto d = _dwrap.get_debugger();
          if (d && d->get_domain().get_domid() == domid) {
            std::cout << "Already attached." << std::endl;
            return;
          }

          //_dwrap.attach(domid);
          //const auto domain = _debugger.get_current_domain().value();
          //std::cout << "Attached to guest " << domain.get_domid() << " (" << domain.get_name() << ")." << std::endl;
          // TODO
        };
      }),

    Verb("detach", "Detach from the current domain.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto& domain = _dwrap.get_domain_or_fail();
          const auto domid = domain.get_domid();
          const auto name = domain.get_name();
          std::cout << "Detached from guest " << domid << " (" << name << ")." << std::endl;
          _dwrap.detach();
        };
      }),

    Verb("pause", "Pause the current domain",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          _dwrap.get_domain_or_fail().pause();
        };
      }),

    Verb("unpause", "Unpause the current domain",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          _dwrap.get_domain_or_fail().unpause();
        };
      }),
  }));

  _repl.add_command(make_command("info", "Query the state of Xen, the attached guest and its registers.", {
      Verb("guest", "Query the state of the current guest.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            // TODO: handle not being attached yet
            //auto &domain = _dwrap.get_domain_or_fail();
            //print_domain_info(domain);
          };
        }),
      Verb("registers", "Query the register state of the current domain.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            auto &domain = _dwrap.get_domain_or_fail();
            auto regs = domain.get_cpu_context(0);
            //print_registers(regs);
          };
        }),
      Verb("variables", "Query variables.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            /*
            for (const auto& var : _variables) {
              std::cout << var.first << "\t" << var.second << std::endl;
            }
             */
          };
        }),
      Verb("xen", "Query Xen version and capabilities.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            //print_xen_info(_dwrap.get_xen_handle());
          };
        }),
  }));

  /**
   * print <expr>
   */

  _repl.add_command(make_command(
      Verb("print", "Display the value of an expression.",
        {
          Flag('f', "format", "Format.", {
            Argument("fmt", "The format to use.",
                make_match_one_of<std::string::const_iterator, std::vector<std::string>>({"b", "x", "d"}),
                [](const auto&, const auto&) {
                  return std::vector<std::string>{"b", "x", "d"};
                }),
          })
        },
        {
          Argument("expr", "The expression to display.", match_everything<std::string::const_iterator>),
        },
        [this](auto &flags, auto &args) {
          const auto print_as_dec = [](std::ostream &out, uint64_t result) {
            out << std::dec << result;
          };
          const auto print_as_hex = [](std::ostream &out, uint64_t result) {
            out << std::showbase << std::hex << result << std::dec;
          };
          const auto print_as_bin = [](std::ostream &out, uint64_t result) {
            // TODO: don't print leading zeroes?
            out << "0b" << std::bitset<CHAR_BIT * sizeof(uint64_t)>(result);
          };

          std::function<void(std::ostream&, uint64_t)> printer = print_as_hex;
          if (flags.has('f')) {
            const auto format = flags.get('f').value().get(0);
            assert(format.size() == 1);
            switch (format[0]) {
              case 'x':
                printer = print_as_hex;
                break;
              case 'b':
                printer = print_as_bin;
                break;
              case 'd':
                printer = print_as_dec;
                break;
              default:
                printer = print_as_hex;
                break;
            }
          }

          const auto expr_str = args.get("expr");
          return [this, expr_str, printer]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);
            const auto result = _dwrap.evaluate_expression(expr);
            printer(std::cout, result);
            std::cout << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("set", "Write to a variable, register, or memory region.",
        {
          Flag('w', "word-size", "Size of each word to read.", {
              Argument("size", "The size of the word to set (b/h/w/g).",
                  make_match_one_of<std::string::const_iterator, std::vector<std::string>>({"b", "h", "w", "g"}),
                  [](const auto& a, const auto& b) {
                    return std::vector<std::string>{"b", "h", "w", "g"};
                  }),
          }),
        },
        {
          Argument("{$var, *expr} = expr", "", match_everything<std::string::const_iterator>),
        },
        [this](auto &flags, auto &args) {
          const auto expr_str = args.get(0);

          size_t word_size = 0;
          const auto word_size_flag = flags.get('w');

          if (word_size_flag) {
            const auto word_size_str = word_size_flag.value().get(0);
            switch (word_size_str[0]) {
              case 'b':
                word_size = 1;
                break;
              case 'h':
                word_size = 2;
                break;
              case 'w':
                word_size = 4;
                break;
              case 'g':
                word_size = 8;
                break;
            }
          }

          return [this, expr_str, word_size]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);
            _dwrap.evaluate_set_expression(expr,
                word_size ? word_size : _dwrap.get_domain_or_fail().get_word_size());
          };
        })));

  _repl.add_command(make_command(
      Verb("unset", "Unset a variable.",
        {},
        {
          Argument("$var", "", match_everything<std::string::const_iterator>),
        },
        [this](auto &/*flags*/, auto &args) {
          const auto expr_str = args.get("$var");
          return [this, expr_str]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);

            // Make sure the expr is of the form $var
            if (!expr.template is_of_type<Variable>())
              throw InvalidInputException("'" + expr_str + "' is not a variable!");

            const auto name = expr.template as<Variable>().value;
            _dwrap.delete_var(name);
          };
        })));

  _repl.add_command(make_command(
      Verb("examine", "Read memory.",
        {
          Flag('w', "word-size", "Size of each word to read.", {
              Argument("size", "The size of the word to read (b/h/w/g).",
                  make_match_one_of<std::string::const_iterator, std::vector<std::string>>({"b", "h", "w", "g"}),
                  [](const auto& a, const auto& b) {
                    return std::vector<std::string>{"b", "h", "w", "g"};
                  }),
          }),
          Flag('n', "num-words", "Number of words to read.", {
              Argument("num", "The number of words to read.", match_number_unsigned<std::string::const_iterator>),
          })
        },
        {
          Argument("expr", "", match_everything<std::string::const_iterator>),
        },
        [this](auto &flags, auto &args) {
          const auto expr_str = args.get(0);

          size_t word_size = 0;
          const auto word_size_flag = flags.get('w');

          if (word_size_flag) {
            const auto word_size_str = word_size_flag.value().get(0);
            switch (word_size_str[0]) {
              case 'b':
                word_size = 1;
                break;
              case 'h':
                word_size = 2;
                break;
              case 'w':
                word_size = 4;
                break;
              case 'g':
                word_size = 8;
                break;
            }
          }

          size_t num_words = 1;
          const auto num_words_flag = flags.get('n');
          if (num_words_flag) {
            num_words = std::stoul(num_words_flag.value().get(0));
          }

          return [this, expr_str, word_size, num_words]() {
            Parser parser;
            const auto expr = parser.parse(expr_str);
            const auto addr = _dwrap.evaluate_expression(expr);
            examine(
                addr,
                word_size ? word_size : _dwrap.get_domain_or_fail().get_word_size(),
                num_words);
          };
        })));

  _repl.add_command(make_command("breakpoint", "Manage breakpoints.", {
    Verb("create", "Create a breakpoint.",
      {},
      {
        Argument("addr", "The address at which to create a breakpoint.",
            match_everything<std::string::const_iterator>)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto address_str = args.get(0);

        return [this, address_str]() {
          // TODO
          //Parser parser;
          //const auto address_expr = parser.parse(address_str);
          //const auto address = evaluate_expression(address_expr);
          //const auto id = _debugger.create_breakpoint(address);
          //std::cout << "Created breakpoint #" << id << "." << std::endl;
        };
      }),
    Verb("delete", "Delete a breakpoint.",
      {},
      {
        Argument("id", "The ID of a breakpoint to delete.", match_number_unsigned<std::string::const_iterator>)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto id = std::stoul(args.get(0));
        return [this, id]() {
          // TODO
          //_debugger.delete_breakpoint(id);
          std::cout << "Deleted breakpoint #" << id << "." << std::endl;
        };
      }),
    Verb("list", "List breakpoints.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          /* TODO
          const auto bps = _debugger.get_breakpoints();
          std::cout << std::showbase << std::hex;
          for (const auto pair : bps) {
            std::cout << pair.first << ":\t" << pair.second.address << std::endl;
          }
          std::cout << std::dec;
           */
        };
      }),
    }));

  _repl.add_command(make_command(
      Verb("continue", "Continue until the next breakpoint.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            _dwrap.get_debugger()->continue_();
            // TODO
            //std::cout << "Hit breakpoint #" << bp.id << "." << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("step", "Step forward one instruction.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            _dwrap.get_debugger()->single_step();
          };
        })));
}

/* TODO
void DebuggerREPL::print_domain_info(const xen::Domain &domain) {
  const auto dominfo = domain.get_info();

  std::cout
    << "Domain " << domain.get_domid() << " (" << domain.get_name() << "):" << std::endl
    << domain.get_word_size() * 8 << "-bit " << (dominfo.hvm ? "HVM" : "PV") << std::endl
    << (dominfo.max_vcpu_id+1) << " VCPUs" << std::endl
    << (dominfo.paused ? "Paused" : "Running") << std::endl
    << (dominfo.crashed ? "Crashed" : "")
    << std::endl;
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

  std::cout << std::dec;
}

void DebuggerREPL::print_xen_info(const xen::XenHandle &xen) {
  auto version = xen.get_xenctrl().get_xen_version();
  std::cout << "Xen " << version.major << "." << version.minor << std::endl;
}
*/

void DebuggerREPL::examine(uint64_t address, size_t word_size, size_t num_words) {
  auto mem_handle = _dwrap.examine(address, word_size, num_words);
  auto mem = (char*)mem_handle.get();

  const auto newline_limit = 3*sizeof(uint64_t)/word_size;

  std::cout << std::hex << std::showbase;
  std::cout << address << " to " << address + word_size*num_words << ":" << std::endl;
  std::cout << std::noshowbase << std::setfill('0');
  for (size_t i = 0; i < num_words; ++i) {
    char *target = mem+(i+1)*word_size;
    for (size_t j = 0; j < word_size; ++j) {
      std::cout << std::setw(2) << (((uint32_t)(*--target)) & 0xFF);
    }
    std::cout << " ";

    if (i != num_words-1 && (i % newline_limit) == newline_limit-1)
      std::cout << std::endl;
  }
  std::cout << std::dec << std::endl;
}
