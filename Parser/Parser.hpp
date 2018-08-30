//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_PARSER_HPP
#define XENDBG_PARSER_HPP

#include <cstdint>
#include <queue>
#include <stack>
#include <string>
#include <variant>

#include "ParserException.hpp"
#include "Sentinel.hpp"
#include "Expression/ExpressionGeneric.hpp"
#include "Token/Constant.hpp"
#include "Token/Label.hpp"
#include "Token/Symbol.hpp"
#include "Token/Variable.hpp"
#include "Expression/Expression.hpp"
#include "Expression/Operator/Precedence.hpp"
#include "Expression/Operator/BinaryOperator.hpp"
#include "Expression/Operator/UnaryOperator.hpp"
#include "../Util/overloaded.hpp"

namespace xd::parser {

  class Parser {
  public:
    expr::Expression parse(std::string input);

  private:
    using Token = std::variant<
        token::Constant,
        token::Label,
        token::Symbol,
        token::Variable>;
    using Operator = std::variant<
        expr::op::Sentinel,
        expr::op::Negate, expr::op::Dereference,
        expr::op::Add, expr::op::Subtract, expr::op::Multiply, expr::op::Divide,
        expr::op::Equals>;

  private:
    static Operator symbol_to_binop(const token::Symbol& symbol);
    static Operator symbol_to_unop(const token::Symbol& symbol);

  private:
    void consume();
    const Token& next_token();

    void parse_expression();
    void parse_unit();

    void push_operator_and_merge(Operator op);
    void pop_operator_and_merge();

    template <typename Predicate_t>
    void expect(Predicate_t predicate, const std::string& msg) {
      if (_tokens.empty()) {
        throw except::ExpectMissingTokenException(_input, msg);
      } else if (predicate(next_token())) {
        consume();
      } else {
        throw except::ExpectWrongTokenException(_input, _tokens_pos.front(), msg);
      }
    };

  private:
    std::string _input;
    std::queue<Token> _tokens;
    std::queue<size_t> _tokens_pos;
    std::stack<Operator> _operators;
    std::stack<expr::Expression> _operands;
  };

}

#endif //XENDBG_PARSER_HPP
