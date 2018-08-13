//
// Created by Spencer Michaels on 8/12/18.
//

#include "Match.hpp"

using xd::parser::token::TokenMatchResult ;
using xd::parser::token::Constant;
using xd::parser::token::Label;
using xd::parser::token::Symbol;
using xd::parser::token::Variable;

template <>
TokenMatchResult<Constant> xd::parser::token::match_token<Constant>(
    std::string::const_iterator begin, std::string::const_iterator end)
{
  std::regex r("^(0[xb])?[0-9]+");
  std::smatch m;

  if (!std::regex_search(begin, end, m, r))
    return std::make_pair(std::optional<Constant>(), begin);

  auto value = std::stoi(m.str(), 0, 0);
  auto new_begin = begin + m.position() + m.length();

  return std::make_pair(Constant(value), new_begin);
};

template <>
TokenMatchResult<Label> xd::parser::token::match_token<Label>(
    std::string::const_iterator begin, std::string::const_iterator end)
{
  std::regex r("^\\&[A-Za-z][A-Za-z0-9_]*");
  std::smatch m;

  if (!std::regex_search(begin, end, m, r))
    return std::make_pair(std::optional<Label>(), begin);

  auto new_begin = begin + m.position() + m.length();

  return std::make_pair(Label(m.str()), new_begin);
}

template <>
TokenMatchResult<Symbol> xd::parser::token::match_token<Symbol>(
    std::string::const_iterator begin, std::string::const_iterator end)
{
  using Type = Symbol::Type;

  Type type;
  switch (*begin) {
    case '+':
      type = Type::Plus;
      break;
    case '-':
      type = Type::Minus;
      break;
    case '*':
      type = Type::Star;
      break;
    case '/':
      type = Type::Slash;
      break;
    case '(':
      type = Type::ParenLeft;
      break;
    case ')':
      type = Type::ParenRight;
      break;
    case '=':
      type = Type::Equals;
      break;
    default:
      return std::make_pair(std::optional<Symbol>(), begin);
  }

  return std::make_pair(Symbol(type), begin + 1);
}

template <>
TokenMatchResult<Variable> xd::parser::token::match_token<Variable>(
    std::string::const_iterator begin, std::string::const_iterator end)
{
  std::regex r("^\\$[A-Za-z][A-Za-z0-9_]*");
  std::smatch m;

  if (!std::regex_search(begin, end, m, r))
    return std::make_pair(std::optional<Variable>(), begin);

  auto new_begin = begin + m.position() + m.length();
  auto name = m.str().substr(1);

  return std::make_pair(Variable(name), new_begin);
}
