//
// Created by Spencer Michaels on 8/28/18.
//

#include <iomanip>
#include <iostream>
#include <stdexcept>

#include <elfio/elfio.hpp>

#include <Util/string.hpp>
#include <Xen/XenException.hpp>
#include <Xen/Xen.hpp>

#include "DebuggerREPL.hpp"
#include "Parser/Parser.hpp"
#include "Command/Argument.hpp"
#include "Command/Flag.hpp"
#include "Command/MakeCommand.hpp"
#include "Command/Match.hpp"
#include "Command/MatchHelper.hpp"
#include "Command/Verb.hpp"

#define STEP_PRINT_INSTRS 4

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
  : _loop(uvw::Loop::getDefault()),
    _signal(_loop->resource<uvw::SignalHandle>()),
    _dwrap(repl::DebuggerWrapper(_loop, non_stop_mode)),
    _vcpu_id(0)
{
  setup_repl();
}

void DebuggerREPL::stop() {
  _loop->walk([](auto &handle) {
    if (!handle.closing())
      handle.close();
  });

  _loop->run();
  _loop->close();

  std::cout << "Goodbye!" << std::endl;
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
    } catch (const NoSuchDomainException&e) {
      std::cout << "No such domain: " << e.what() << std::endl;
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
    } catch (const NotSupportedException &e) {
      std::cout << "Unsupported feature: " << e.what() << std::endl;
    } catch (const repl::NoGuestAttachedException &e) {
      std::cout << "Not attached to a guest! Use 'guest attach <domid/name>'." << std::endl;
    } catch (const repl::NoSuchBreakpointException &e) {
      std::cout << "No such breakpoint!" << std::endl;
    } catch (const repl::NoSuchWatchpointException &e) {
      std::cout << "No such breakpoint!" << std::endl;
    }
  });

  stop();
  exit(0);
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

  _repl.add_command(make_command("cpu", "Get/set the current CPU.", {
    Verb("get", "Get the current CPU.",
      {},
      {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          _dwrap.get_debugger_or_fail();
          std::cout << "CPU " << _vcpu_id << " (max: " << _max_vcpu_id << ")" << std::endl;
        };
      }),
    Verb("set", "Switch to a new CPU.",
      {},
      {
        Argument("id", "The ID of the CPU to switch to.",
            match_number_unsigned<std::string::const_iterator>)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto id = std::stoul(args.get(0));
        return [this, id]() {
          _dwrap.get_debugger_or_fail();

          if (id > _max_vcpu_id) {
            std::cout << "CPU ID too high! Max is " << _max_vcpu_id << "." << std::endl;
            return;
          }

          _vcpu_id = id;
          _dwrap.set_vcpu_id(_vcpu_id);
          std::cout << "Switched to CPU " << _vcpu_id << "." << std::endl;
        };
      }),
    }));

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
          const auto domains = _dwrap.get_xen().get_domains();
          for (const auto &domain : domains) {
            std::cout << xen::Xen::get_domid_any(domain) << "\t"
                << xen::Xen::get_name_any(domain) << std::endl;
          }
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
                auto domains = _dwrap.get_xen().get_domains();
                std::transform(domains.begin(), domains.end(),
                  std::back_inserter(options), [](const auto& domain) {
                    return xen::Xen::get_name_any(domain);
                  });
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
            domid = (unsigned short)-1;
          }

          std::optional<xen::DomainAny> domain;
          if (domid != (unsigned short)-1) {
            domain = _dwrap.get_xen().get_domain_from_domid(domid);
          } else {
            domain = _dwrap.get_xen().get_domain_from_name(domid_or_name);
            if (domain)
              domid = xen::Xen::get_domid_any(*domain);
          }

          if (!domain)
            throw NoSuchDomainException(domid_or_name);

          auto dbg = _dwrap.get_debugger();
          if (dbg && dbg->get_domain().get_domid() == domid) {
            std::cout << "Already attached." << std::endl;
            return;
          }

          _dwrap.attach(*domain);

          auto &d = _dwrap.get_domain_or_fail();
          _max_vcpu_id = d.get_dominfo().max_vcpu_id;
          auto word_size = d.get_word_size();

          const auto mode =
              (word_size == sizeof(uint64_t)) ? CS_MODE_64 : CS_MODE_32;

          if (cs_open(CS_ARCH_X86, mode, &_capstone) != CS_ERR_OK)
            throw CapstoneException("Failed to open Capstone handle!");

          cs_option(_capstone, CS_OPT_DETAIL, CS_OPT_ON);

          std::cout << "Attached to guest " << domid << " (" << xen::Xen::get_name_any(*domain) << ")." << std::endl;
        };
      }),

    Verb("detach", "Detach from the current domain.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto& domain = _dwrap.get_domain_or_fail();
          const auto domid = domain.get_domid();
          const auto name = domain.get_name();

          _dwrap.detach();
          cs_close(&_capstone);

          std::cout << "Detached from guest " << domid << " (" << name << ")." << std::endl;
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
            auto &domain = _dwrap.get_domain_or_fail();
            print_domain_info(domain);
          };
        }),
      Verb("registers", "Query the register state of the current domain.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            auto &domain = _dwrap.get_domain_or_fail();
            auto regs = domain.get_cpu_context(_vcpu_id);
            print_registers(regs);
          };
        }),
      Verb("variables", "Query variables.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            for (const auto& var : _dwrap.get_variables()) {
              std::cout << var.first << "\t" << var.second << std::endl;
            }
          };
        }),
      Verb("xen", "Query Xen version and capabilities.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            print_xen_info(_dwrap.get_xen());
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
    Verb("disassemble", "Disassemble instructions.",
      {},
      {
        Argument("addr", "The start address.",
            match_optionally_quoted_string<std::string::const_iterator>),
        Argument("len", "The number of bytes to read.",
            match_optionally_quoted_string<std::string::const_iterator>),
      },
      [this](auto &/*flags*/, auto &args) {
        const auto address_str = args.get(0);
        const auto len_str = args.get(1);

        return [this, address_str, len_str]() {
          Parser parser;
          const auto address_expr = parser.parse(address_str);
          const auto address = _dwrap.evaluate_expression(address_expr);

          const auto len_expr = parser.parse(len_str);
          const auto len = _dwrap.evaluate_expression(len_expr);

          disassemble(address, len);
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
              Argument("num", "The number of words to read.", match_optionally_quoted_string<std::string::const_iterator>),
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
          Parser parser;
          const auto address_expr = parser.parse(address_str);
          const auto address = _dwrap.evaluate_expression(address_expr);
          const auto id = _dwrap.insert_breakpoint(address);
          std::cout << "Created breakpoint #" << id << "." << std::endl;
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
          _dwrap.remove_breakpoint(id);
          std::cout << "Deleted breakpoint #" << id << "." << std::endl;
        };
      }),
    Verb("list", "List breakpoints.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto bps = _dwrap.get_breakpoints();
          std::cout << std::showbase;
          for (const auto pair : bps) {
            std::cout << std::dec << pair.first << ":\t" << std::hex << pair.second << std::endl;
          }
          std::cout << std::dec;
        };
      }),
    }));

  _repl.add_command(make_command(
      Verb("continue", "Continue until the next breakpoint.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            bool interrupted = false;
            _dwrap.get_debugger_or_fail()->on_stop([this](auto /*reason*/) {
              _loop->stop();
            });
            _signal->once<uvw::SignalEvent>([this, &interrupted](const auto &event, auto &handle) {
              interrupted = true;
              handle.loop().stop();
            });
            _signal->start(SIGINT);
            _dwrap.get_debugger_or_fail()->continue_();
            _loop->run();
            _signal->stop();

            auto ctx = _dwrap.get_debugger_or_fail()->get_domain().get_cpu_context(_vcpu_id);
            auto ip = std::visit(util::overloaded {
              [](const reg::x86_32::RegistersX86_32 &regs) {
                return (uint64_t)regs.template get<reg::x86_32::eip>();
              },
              [](const reg::x86_64::RegistersX86_64 &regs) {
                return (uint64_t)regs.template get<reg::x86_64::rip>();
              }
            }, ctx);
            const auto &bps = _dwrap.get_breakpoints();
            auto it = std::find_if(bps.begin(), bps.end(),
              [&](auto pair) {
                auto [id, addr] = pair;
                return addr == ip;
              });
            if (interrupted)
              std::cout << "Interrupted." << std::endl;
            else if (it != bps.end())
              std::cout << "Hit breakpoint #" << it->first << "." << std::endl;
            else
              std::cout << "Hit a breakpoint, but no ID is associated with it." << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("step", "Step forward one instruction.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            _dwrap.get_debugger()->single_step();

            auto ctx = _dwrap.get_debugger_or_fail()->get_domain().get_cpu_context(_vcpu_id);
            auto ip = std::visit(util::overloaded {
              [](const reg::x86_32::RegistersX86_32 &regs) {
                return (uint64_t)regs.template get<reg::x86_32::eip>();
              },
              [](const reg::x86_64::RegistersX86_64 &regs) {
                return (uint64_t)regs.template get<reg::x86_64::rip>();
              }
            }, ctx);
            disassemble(ip, X86_MAX_INSTRUCTION_SIZE*STEP_PRINT_INSTRS, STEP_PRINT_INSTRS);
          };
        })));

  _repl.add_command(make_command("watchpoint", "Manage watchpoints..", {
    Verb("create", "Create a watchpoint.",
      {},
      {
        Argument("addr", "The address at which to create a watchpoint.",
            match_number_unsigned<std::string::const_iterator>),
        Argument("len", "The length of the region to watch.",
            match_number_unsigned<std::string::const_iterator>),
        Argument("type", "The type of the watchpoint (r/w/a).",
            make_match_one_of<std::string::const_iterator,
              std::vector<std::string>>({"r", "w", "a"})),
      },
      [this](auto &/*flags*/, auto &args) {
        const auto address_str = args.get(0);
        const auto len_str = args.get(1);
        const auto type_str = args.get(2);

        return [this, address_str, len_str, type_str]() {
          if (!_dwrap.is_hvm())
            throw NotSupportedException("Watchpoints are only supported on HVM guests.");

          Parser parser;
          const auto address_expr = parser.parse(address_str);
          const auto address = _dwrap.evaluate_expression(address_expr);

          const auto len_expr = parser.parse(len_str);
          const auto len = _dwrap.evaluate_expression(len_expr);

          if (type_str.size() != 1)
            throw InvalidInputException("Type must be one of: r, w, a");

          WatchpointType type;
          switch (type_str[0]) {
            case 'r':
              type = WatchpointType::Read;
              break;
            case 'w':
              type = WatchpointType::Write;
              break;
            case 'a':
              type = WatchpointType::Access;
              break;
            default:
              throw InvalidInputException("Type must be one of: r, w, a");
          }

          const auto id = _dwrap.insert_watchpoint(address, len, type);
          std::cout << "Created watchpoint #" << id << "." << std::endl;
        };
      }),
    Verb("delete", "Delete a watchpoint.",
      {},
      {
        Argument("id", "The ID of a watchpoint to delete.",
            match_number_unsigned<std::string::const_iterator>)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto id = std::stoul(args.get(0));
        return [this, id]() {
          if (!_dwrap.is_hvm())
            throw NotSupportedException("Watchpoints are only supported on HVM guests.");

          _dwrap.remove_watchpoint(id);
          std::cout << "Deleted watchpoint #" << id << "." << std::endl;
        };
      }),
    Verb("list", "List watchpoints.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          if (!_dwrap.is_hvm())
            throw NotSupportedException("Watchpoints are only supported on HVM guests.");

          const auto bps = _dwrap.get_watchpoints();
          std::cout << std::showbase;
          for (const auto pair : bps) {
            std::string type;
            switch (pair.second.type) {
              case WatchpointType::Access:
                type = "access";
                break;
              case WatchpointType::Read:
                type = "read";
                break;
              case WatchpointType::Write:
                type = "write";
                break;
            }

            std::cout << std::dec << pair.first << ":\t"
              << std::showbase << std::hex << pair.second.address << " +"
              << pair.second.length << " "
              << type << std::endl;
          }
          std::cout << std::dec;
        };
      }),
    }));

}

void DebuggerREPL::print_domain_info(const xen::Domain &domain) {
  const auto dominfo = domain.get_dominfo();
  std::cout
    << "Domain " << domain.get_domid() << " (" << domain.get_name() << "):" << std::endl
    << domain.get_word_size() * 8 << "-bit " << (dominfo.hvm ? "HVM" : "PV") << std::endl
    << (dominfo.max_vcpu_id+1) << " VCPUs" << std::endl
    << (dominfo.paused ? "Paused" : "Running") << std::endl
    << (dominfo.crashed ? "Crashed" : "")
    << std::endl;
}

void DebuggerREPL::print_registers(const reg::RegistersX86Any& regs) {
  std::cout << std::hex << std::showbase;

  std::visit(util::overloaded {
    [](const reg::x86_32::RegistersX86_32 regs) {
      regs.for_each([](const auto &md, auto reg) {
        std::cout << md.name << "\t" << (uint64_t)reg << std::endl;
      });
    },
    [](const reg::x86_64::RegistersX86_64 regs) {
      regs.for_each([](const auto &md, auto reg) {
        std::cout << md.name << "\t" << (uint64_t)reg << std::endl;
      });
    }
  }, regs);

  std::cout << std::dec;
}

void DebuggerREPL::print_xen_info(const xen::Xen &xen) {
  auto version = xen.xenctrl.get_xen_version();
  std::cout << "Xen " << version.major << "." << version.minor << std::endl;
}

void DebuggerREPL::disassemble(uint64_t address, size_t length, size_t max_instrs) {
  auto mem_handle = _dwrap.examine(address, 1, length);
  auto mem = mem_handle.get();

  cs_insn *insn;
  auto count = cs_disasm(_capstone, mem, length, address, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count && j < max_instrs; j++) {
      printf("0x%lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
          insn[j].op_str);
    }

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");
}

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
