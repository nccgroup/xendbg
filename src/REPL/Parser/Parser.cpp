//
// Copyright (C) 2018-2019 Spencer Michaels
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Created by Spencer Michaels on 8/11/18.
//

#include <iostream>
#include <stdexcept>
#include <functional>

#include "Predicate.hpp"
#include "Parser.hpp"
#include "Tokenizer.hpp"
#include "Token/Constant.hpp"
#include "Token/Match.hpp"
#include "Predicate.hpp"
#include "Token/Symbol.hpp"
#include "Token/Variable.hpp"
#include <Util/clear.hpp>
#include <Util/pop_ret.hpp>

using xd::parser::Parser;
using xd::parser::except::MissingExpressionException;
using xd::parser::except::MissingOperandException;
using xd::parser::except::NoSuchBinaryOperatorException;
using xd::parser::except::NoSuchUnaryOperatorException;
using xd::parser::expr::Expression;
using xd::parser::expr::op::BinaryOperator;
using xd::parser::expr::op::precedence_of;
using xd::parser::expr::op::Sentinel;
using xd::parser::expr::op::UnaryOperator;
using xd::parser::pred::is_binary_operator_symbol;
using xd::parser::pred::is_constant;
using xd::parser::pred::is_label;
using xd::parser::pred::is_sentinel;
using xd::parser::pred::is_symbol;
using xd::parser::pred::is_symbol_of_type;
using xd::parser::pred::is_unary_operator_symbol;
using xd::parser::pred::is_variable;
using xd::parser::token::Symbol;
using xd::parser::tokenizer::tokenize;
using xd::util::clear;
using xd::util::pop_ret;


Parser::Operator Parser::symbol_to_binop(const Symbol& symbol) {
  using Type = Symbol::Type;

  switch (symbol.type()) {
    case Type::Plus:
      return expr::op::Add();
    case Type::Minus:
      return expr::op::Subtract();
    case Type::Star:
      return expr::op::Multiply();
    case Type::Slash:
      return expr::op::Divide();
    case Type::Equals:
      return expr::op::Equals();
    default:
      throw NoSuchBinaryOperatorException(symbol);
  }
};

Parser::Operator Parser::symbol_to_unop(const Symbol& symbol) {
  using Type = Symbol::Type;

  switch (symbol.type()) {
    case Type::Minus:
      return expr::op::Negate();
    case Type::Star:
      return expr::op::Dereference();
    default:
      throw NoSuchUnaryOperatorException(symbol);
  }
};

Expression Parser::parse(std::string input) {

  _input = input;
  clear(_operands);
  clear(_operators);
  clear(_tokens);

  tokenize(input, _tokens, _tokens_pos);

  _operators.push(Sentinel());
  parse_expression();
  if (!_tokens.empty()) {
    throw except::ExtraTokenException(_input, _tokens_pos.front());
  }

  return std::move(_operands.top());
}

void Parser::consume() {
  _tokens.pop();
  _tokens_pos.pop();
}

const Parser::Token& Parser::next_token() {
  if (_tokens.empty())
    throw MissingExpressionException(_input, _input.size());
  return _tokens.front();
}

void Parser::parse_expression() {
  parse_unit();

  while (!_tokens.empty() && is_binary_operator_symbol(next_token())) {
    push_operator_and_merge(
        symbol_to_binop(
            std::get<token::Symbol>(next_token())));
    consume();

    if (_tokens.empty())
      throw except::MissingExpressionException(_input, _input.size());
    parse_unit();
  }

  while (!is_sentinel(_operators.top())) {
    pop_operator_and_merge();
  }
}

void Parser::parse_unit() {
  const auto& next = next_token();

  if (is_constant(next)) {
    const auto value = std::get<token::Constant>(next).value();
    _operands.emplace(expr::Constant{value});
    consume();
  } else if (is_label(next)) {
    const auto name = std::get<token::Label>(next).name();
    _operands.emplace(expr::Label{name});
    consume();
  } else if (is_variable(next)) {
    const auto name = std::get<token::Variable>(next).name();
    _operands.emplace(expr::Variable{name});
    consume();
  } else if (is_symbol_of_type(next, Symbol::Type::ParenLeft)) {
    consume();
    _operators.push(Sentinel());
    parse_expression();
    expect([](auto&& token) {
      return is_symbol_of_type(token, Symbol::Type::ParenRight);
    }, "Expected close-paren!");
    _operators.pop();
  } else if (is_unary_operator_symbol(next)) {
    push_operator_and_merge(
        symbol_to_unop(
            std::get<token::Symbol>(next)));
    consume();
    parse_unit();
  } else {
    throw except::MissingExpressionException(_input, _tokens_pos.front());
  }
}

void xd::parser::Parser::push_operator_and_merge(Parser::Operator op) {
  while (precedence_of(_operators.top()) > precedence_of(op)) {
    pop_operator_and_merge();
  }
  _operators.push(op);
}

void xd::parser::Parser::pop_operator_and_merge() {
  std::visit(util::overloaded {
    [](const Sentinel& op) {
      throw except::SentinelMergeException();
    },
    [this](const UnaryOperator& op) {
      if (_operands.empty()) {
        const auto pos = _tokens_pos.empty() ? _input.size() : _tokens_pos.front();
        throw MissingOperandException(_input, pos);
      }

      auto x = pop_ret(_operands);
      _operands.emplace(op, std::move(x));
    },
    [this](const BinaryOperator& op) {
      if (_operands.size() < 2) {
        const auto pos = _tokens_pos.empty() ? _input.size() : _tokens_pos.front();
        throw MissingOperandException(_input, pos);
      }

      auto y = pop_ret(_operands);
      auto x = pop_ret(_operands);
      _operands.emplace(op, std::move(x), std::move(y));
    }
  }, pop_ret(_operators));
}

