//
// Created by smichaels on 1/7/19.
//

#include <elfio/elfio.hpp>

#include "DebuggerWrapper.hpp"

#include <Debugger/DebuggerHVM.hpp>
#include <Debugger/DebuggerPV.hpp>

using xd::parser::expr::Expression;
using xd::parser::expr::Constant;
using xd::parser::expr::Label;
using xd::parser::expr::Variable;
using xd::repl::DebuggerWrapper;
using xd::xen::Xen;

using namespace xd::parser::expr::op;

DebuggerWrapper::DebuggerWrapper(bool non_stop_mode)
  : _xen(Xen::create()),
    _loop(uvw::Loop::getDefault()),
    _non_stop_mode(non_stop_mode),
    _vcpu_id(0)
{
}

void DebuggerWrapper::attach(xd::xen::DomainAny domain_any) {
  _debugger = std::visit(util::overloaded {
      [&](xen::DomainHVM domain) {
        return std::static_pointer_cast<dbg::Debugger>(
            std::make_shared<dbg::DebuggerHVM>(
                *_loop, std::move(domain), _xen->xendevicemodel, _xen->xenevtchn, _non_stop_mode));
      },
      [&](xen::DomainPV domain) {
        return std::static_pointer_cast<dbg::Debugger>(
            std::make_shared<dbg::DebuggerPV>(*_loop, std::move(domain)));
      },
  }, domain_any);

  _debugger->attach();
  load_symbols_from_file(_debugger->get_domain().get_kernel_path());
}

void DebuggerWrapper::detach() {
  _debugger->detach();

  _debugger.reset();
  _variables.clear();
  _symbols.clear();
}

void DebuggerWrapper::assert_attached() {
  if (!_debugger)
    throw NoGuestAttachedException();
}

void DebuggerWrapper::load_symbols_from_file(const std::string &filename) {
  ELFIO::elfio reader;

  if (!reader.load(filename))
    throw std::runtime_error("Failed to read file!");

  _symbols.clear();

  for (const auto section : reader.sections) {
    if (section->get_type() == SHT_SYMTAB) {
      const ELFIO::symbol_section_accessor symbols(reader, section);
      const size_t num_symbols = symbols.get_symbols_num();
      for (size_t i = 0; i < num_symbols; ++i) {
        std::string       name;
        ELFIO::Elf64_Addr address;
        ELFIO::Elf_Xword  size;
        unsigned char     bind;
        unsigned char     type;
        ELFIO::Elf_Half   section_index;
        unsigned char     other;

        symbols.get_symbol(i, name, address, size, bind, type, section_index, other);

        // TODO: very basic for now; just load functions with known addresses
        if (type == STT_FUNC && address > 0)
          _symbols[name] = Symbol{address};
      }
    }
  }
}

const DebuggerWrapper::Symbol &DebuggerWrapper::lookup_symbol(const std::string &name) {
  if (!_symbols.count(name))
    throw NoSuchSymbolException(name);
  return _symbols.at(name);
}

uint64_t DebuggerWrapper::get_var(const std::string &name) {
  if (!_variables.count(name))
    throw NoSuchVariableException(name);
  return _variables.at(name);
}

void DebuggerWrapper::set_var(const std::string &name, uint64_t value) {
  _variables[name] = value;
}

void DebuggerWrapper::delete_var(const std::string &name) {
  if (!_variables.count(name))
    throw NoSuchVariableException(name);
  _variables.erase(name);
}

void DebuggerWrapper::evaluate_set_expression(const Expression &expr, size_t word_size) {
  assert(word_size <= sizeof(uint64_t));

  // $var = expr
  const bool lhs_is_var =
      expr.is_binex() && expr.as_binex().x.template is_of_type<Variable>();

  // *expr = expr
  const bool lhs_is_deref =
      expr.is_binex() && expr.as_binex().x.is_unex();

  if ((!lhs_is_var && !lhs_is_deref) || !std::holds_alternative<Equals>(expr.as_binex().op))
    throw InvalidExpressionException("Input must be of the form {$var, *expr} = expr");

  const auto& ex = expr.as_binex();

  if (lhs_is_var) {
    const auto &var_name = ex.x.as<Variable>().value;
    const auto value = evaluate_expression(ex.y);

    assert_attached();
    auto regs = _debugger->get_domain().get_cpu_context(_vcpu_id); // TODO

    std::visit(util::overloaded {
      [&](auto regs) {
        regs.find([&](auto reg) {
          return reg.name == var_name;
        }, [&](const auto &md, auto &reg) {
          reg = value;
        }, [&]() {
          set_var(var_name, value); // not a register
        });
      },
    }, regs);

    _debugger->get_domain().set_cpu_context(regs, _vcpu_id);

  } else /*if (lhs_is_deref)*/ {
    assert_attached();

    const auto address = evaluate_expression(ex.x.as_unex().x);
    const auto value = evaluate_expression(ex.y);

    _debugger->write_memory_retaining_breakpoints(address, word_size, (void*)&value);
  }
}

uint64_t DebuggerWrapper::evaluate_expression(const Expression& expr) {
  return expr.visit<uint64_t>(util::overloaded {
      [](const Constant& ex) {
        return ex.value;
      },
      [this](const Label& ex) {
        const auto label = ex.value;
        return lookup_symbol(label).address;
      },
      [this](const Variable& ex) {
        const std::string &var_name = ex.value;

        assert_attached();
        auto regs = _debugger->get_domain().get_cpu_context(_vcpu_id); // TODO

        uint64_t ret;

        std::visit(util::overloaded {
            [&](const auto &regs) {
              regs.find([&](auto reg) {
                return reg.name == var_name;
              }, [&](const auto &md, auto &reg) {
                ret = reg;
              }, [&]() {
                ret = get_var(var_name); // not a register
              });
            },
        }, regs);

        return ret;
      },
      [this](const Expression::UnaryExpressionPtr& ex) {
        const auto& op = ex->op;
        const auto& x_value = evaluate_expression(ex->x);

        return std::visit(util::overloaded {
            [this, x_value](Dereference) {
              assert_attached();
              // TODO: only reads 64-bit values for now
              const auto mem = _debugger->read_memory_masking_breakpoints(x_value, sizeof(uint64_t));
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
              throw InvalidExpressionException("Use 'set' to modify variables.");
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

xd::dbg::MaskedMemory DebuggerWrapper::examine(uint64_t address, size_t word_size, size_t num_words) {
  assert(word_size <= sizeof(uint64_t));

  assert_attached();

  const uintptr_t end = word_size*num_words;
  return _debugger->read_memory_masking_breakpoints(address, end);
}
