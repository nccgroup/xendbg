//
// Created by Spencer Michaels on 8/28/18.
//

#include <iomanip>
#include <iostream>
#include <stdexcept>

#include "DebuggerREPL.hpp"
#include "../Xen/XenException.hpp"
#include "../Parser/Parser.hpp"
#include "../REPL/Command/Argument.hpp"
#include "../REPL/Command/Flag.hpp"
#include "../REPL/Command/MakeCommand.hpp"
#include "../REPL/Command/Match.hpp"
#include "../REPL/Command/MatchHelper.hpp"
#include "../REPL/Command/Verb.hpp"
#include "../Util/string.hpp"

using xd::dbg::Debugger;
using xd::dbg::DebuggerREPL;
using xd::dbg::InvalidInputException;
using xd::dbg::NoGuestAttachedException;
using xd::dbg::NoSuchSymbolException;
using xd::dbg::NoSuchVariableException;
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
using xd::repl::cmd::match::make_match_one_of;
using xd::repl::cmd::match::match_everything;
using xd::repl::cmd::match::match_number_unsigned;
using xd::repl::cmd::Verb;
using xd::util::string::next_whitespace;
using xd::util::string::match_optionally_quoted_string;

DebuggerREPL::DebuggerREPL() {
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
    } catch (const NoGuestAttachedException &e) {
      std::cout << "No guest! Attach to a guest with 'guest attach' first." << std::endl;
    } catch (const parser::except::ParserException &e) {
      std::cout << "Invalid input! Parse failed at:" << std::endl;
      std::cout << e.input() << std::endl;
      std::cout << std::string(e.pos(), ' ') << "^" << std::endl;
    } catch (const parser::except::ExpectException &e) {
      std::cout << "Invalid input! Parse failed at:" << std::endl;
      std::cout << e.input() << std::endl;
      std::cout << std::string(e.pos(), ' ') << "^" << std::endl;
    } catch (const NoSuchSymbolException &e) {
      std::cout << "No such symbol: " << e.what() << std::endl;
    } catch (const NoSuchVariableException &e) {
      std::cout << "No such variable: " << e.what() << std::endl;
    } catch (const NoSuchBreakpointException &e) {
      std::cout << "No such breakpoint: #" << e.get_id() << std::endl;
    }
  });
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

  _repl.set_custom_completer([this](const std::string &line) {
    // satisfy type-inference
    std::optional<std::vector<std::string>> ret = std::nullopt;

    const auto last_ws_pos = next_whitespace(line.rbegin(), line.rend());
    if (last_ws_pos == line.rend())
      return ret;

    if (*(last_ws_pos-1) == '&') {
      const auto symbol_map = _debugger.get_symbols();
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
          const auto domains = _debugger.get_guest_domains();
          for (const auto &domain : domains) {
            // TODO: formatting
            std::cout << domain.get_name() << "\t" << domain.get_domid() << std::endl;
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
                const auto domains = _debugger.get_guest_domains();
                std::vector<std::string> options;
                std::transform(domains.begin(), domains.end(),
                  std::back_inserter(options), [](const auto& domain) {
                    return domain.get_name();
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
            domid = _debugger.get_xen_handle().get_xenstore()
                .get_domid_from_name(domid_or_name);
          }

          const auto prev_domain = _debugger.get_current_domain();
          if (prev_domain && prev_domain.value().get_domid() == domid) {
            std::cout << "Already attached." << std::endl;
            return;
          }

          _debugger.attach(domid);
          const auto domain = _debugger.get_current_domain().value();
          std::cout << "Attached to guest " << domain.get_domid() << " (" << domain.get_name() << ")." << std::endl;

          const auto kernel_path = domain.get_kernel_path();
          _debugger.load_symbols_from_file(kernel_path);
          std::cout << "Loaded symbols from '" << kernel_path << "'." << std::endl;
        };
      }),

    Verb("detach", "Detach from the current domain.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto& domain = get_domain_or_fail();
          const auto domid = domain.get_domid();
          const auto name = domain.get_name();
          std::cout << "Detached from guest " << domid << " (" << name << ")." << std::endl;

          _debugger.detach();
        };
      }),

    Verb("pause", "Pause the current domain",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          get_domain_or_fail().pause();
        };
      }),

    Verb("unpause", "Unpause the current domain",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          get_domain_or_fail().unpause();
        };
      }),

    Verb("reboot", "Reboot the current domain",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          auto& domain = get_domain_or_fail();
          domain.reboot();
          _debugger.detach();
          _debugger.attach(domain.get_domid());
        };
      }),
  }));

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
        {
          Flag('f', "format", "Format.", {
            Argument("fmt", "The format to use.", make_match_one_of({"b", "x", "d"}),
                [](const auto&, const auto&) {
                  return std::vector<std::string>{"b", "x", "d"};
                }),
          })
        },
        {
          Argument("expr", "The expression to display.", match_everything),
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
            const auto result = evaluate_expression(expr);
            printer(std::cout, result);
            std::cout << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("set", "Write to a variable, register, or memory region.",
        {
          Flag('w', "word-size", "Size of each word to read.", {
              Argument("size", "The size of the word to set (b/h/w/g).",
                  make_match_one_of({"b", "h", "w", "g"}),
                  [](const auto& a, const auto& b) {
                    return std::vector<std::string>{"b", "h", "w", "g"};
                  }),
          }),
        },
        {
          Argument("{$var, *expr} = expr", "", match_everything),
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
            evaluate_set_expression(expr,
                word_size ? word_size : get_domain_or_fail().get_word_size());
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
              throw InvalidInputException("'" + expr_str + "' is not a variable!");

            const auto name = expr.template as<Variable>().value;
            _debugger.delete_var(name);
          };
        })));

  _repl.add_command(make_command(
      Verb("examine", "Read memory.",
        {
          Flag('w', "word-size", "Size of each word to read.", {
              Argument("size", "The size of the word to read (b/h/w/g).",
                  make_match_one_of({"b", "h", "w", "g"}),
                  [](const auto& a, const auto& b) {
                    return std::vector<std::string>{"b", "h", "w", "g"};
                  }),
          }),
          Flag('n', "num-words", "Number of words to read.", {
              Argument("num", "The number of words to read.", match_number_unsigned),
          })
        },
        {
          Argument("expr", "", match_everything),
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
            const auto addr = evaluate_expression(expr);
            examine(
                addr, 
                word_size ? word_size : get_domain_or_fail().get_word_size(),
                num_words);
          };
        })));

  _repl.add_command(make_command("breakpoint", "Manage breakpoints.", {
    Verb("create", "Create a breakpoint.",
      {},
      {
        Argument("addr", "The address at which to create a breakpoint.", match_everything)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto address_str = args.get(0);

        return [this, address_str]() {
          Parser parser;
          const auto address_expr = parser.parse(address_str);
          const auto address = evaluate_expression(address_expr);

          const auto id = _debugger.create_breakpoint(address);
          std::cout << "Created breakpoint #" << id << "." << std::endl;
        };
      }),
    Verb("delete", "Delete a breakpoint.",
      {},
      {
        Argument("id", "The ID of a breakpoint to delete.", match_number_unsigned)
      },
      [this](auto &/*flags*/, auto &args) {
        const auto id = std::stoul(args.get(0));
        return [this, id]() {
          _debugger.delete_breakpoint(id);
          std::cout << "Deleted breakpoint #" << id << "." << std::endl;
        };
      }),
    Verb("list", "List breakpoints.",
      {}, {},
      [this](auto &/*flags*/, auto &/*args*/) {
        return [this]() {
          const auto bps = _debugger.get_breakpoints();
          std::cout << std::showbase << std::hex;
          for (const auto pair : bps) {
            std::cout << pair.first << ":\t" << pair.second.address << std::endl;
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
            const auto bp = _debugger.continue_until_breakpoint();
            std::cout << "Hit breakpoint #" << bp.id << "." << std::endl;
          };
        })));

  _repl.add_command(make_command(
      Verb("step", "Step forward one instruction.",
        {}, {},
        [this](auto &/*flags*/, auto &/*args*/) {
          return [this]() {
            _debugger.single_step();
          };
        })));
}

xd::xen::Domain &DebuggerREPL::get_domain_or_fail() {
  auto& domain = _debugger.get_current_domain();
  if (!domain)
    throw NoGuestAttachedException();
  return domain.value();
}

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

void xd::dbg::DebuggerREPL::evaluate_set_expression(const Expression &expr, size_t word_size) {
  assert(word_size <= sizeof(uint64_t));

  // $var = expr
  const bool lhs_is_var =
    expr.is_binex() && expr.as_binex().x.template is_of_type<Variable>();

  // *expr = expr
  const bool lhs_is_deref =
    expr.is_binex() && expr.as_binex().x.is_unex();

  if ((!lhs_is_var && !lhs_is_deref) || !std::holds_alternative<Equals>(expr.as_binex().op))
    throw InvalidInputException("Input must be of the form {$var, *expr} = expr");

  const auto& ex = expr.as_binex();

  if (lhs_is_var) {
    const auto &var_name = ex.x.as<Variable>().value;
    const auto value = evaluate_expression(ex.y);

    // TODO: VCPU ID
    if (xd::xen::is_register_name(var_name))
      get_domain_or_fail().write_register(var_name, value);
    else
      _debugger.set_var(var_name, value);

  } else /*if (lhs_is_deref)*/ {
    const auto address = evaluate_expression(ex.x.as_unex().x);
    const auto value = evaluate_expression(ex.y);

    const auto mem = get_domain_or_fail().map_memory(
        address, sizeof(uint64_t), PROT_WRITE);
    memcpy((void*)mem.get(), (void*)&value, word_size);
  }
}

uint64_t DebuggerREPL::evaluate_expression(const Expression& expr) {
  return expr.visit<uint64_t>(util::overloaded {
    [](const Constant& ex) {
      return ex.value;
    },
    [this](const Label& ex) {
      const auto label = ex.value;
      return _debugger.lookup_symbol(label).address;
    },
    [this](const Variable& ex) {
      const std::string &var_name = ex.value;

      if (xd::xen::is_register_name(var_name))
        return get_domain_or_fail().read_register(var_name);
      else
        return _debugger.get_var(var_name); 
    },
    [this](const Expression::UnaryExpressionPtr& ex) {
      const auto& op = ex->op;
      const auto& x_value = evaluate_expression(ex->x);

      return std::visit(util::overloaded {
        [this, x_value](Dereference) {
          const auto mem = get_domain_or_fail().map_memory(
              x_value, sizeof(uint64_t), PROT_READ);
          return *((uint64_t*)mem.get());
        },
        [x_value](Negate) {
          return -x_value;
        },
      }, op);
    },
    [this](const Expression::BinaryExpressionPtr& ex) {
      const auto& op = ex->op;
      const auto get_xy = [this, &ex]() {
        return std::make_pair(
            evaluate_expression(ex->x),
            evaluate_expression(ex->y));
      };

      return std::visit(util::overloaded {
        [](Equals) {
          throw InvalidInputException("Use 'set' to modify variables.");
          return 0UL; // satisfy the compiler's type-inference
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
    },
  });
}

void DebuggerREPL::examine(uint64_t address, size_t word_size, size_t num_words) {
  assert(word_size <= sizeof(uint64_t));
  assert(word_size > 0);
  assert(num_words > 0);

  const auto mem_handle = get_domain_or_fail().map_memory(
      address, word_size*num_words, PROT_READ);
  char *mem = (char*)mem_handle.get();

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
