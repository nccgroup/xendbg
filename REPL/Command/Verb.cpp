//
// Created by Spencer Michaels on 8/19/18.
//

#include "Match.hpp"
#include "Verb.hpp"
#include "../../Util/string.hpp"

#include <iostream>
using xd::repl::cmd::Action;
using xd::repl::cmd::ArgsHandle;
using xd::repl::cmd::FlagsHandle;
using xd::repl::cmd::Verb;
using xd::util::string::expect;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;

std::optional<Action> Verb::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  const auto first_non_ws = skip_whitespace(begin, end);
  const auto flags_start = expect(_name, first_non_ws, end);

  if (flags_start == first_non_ws) {
    return std::nullopt;
  }

  auto [flags, flags_end] = match_flags(flags_start, end);
  auto [args, args_end] = match_args(flags_end, end);

  if (args_end != end)
    throw std::runtime_error("Found extra args!"); // TODO

  return _make_action(flags, args);
}

std::pair<FlagsHandle, std::string::const_iterator> Verb::match_flags(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  return xd::repl::cmd::match_flags(begin, end, _flags);
}

std::pair<ArgsHandle, std::string::const_iterator> Verb::match_args(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  return xd::repl::cmd::match_args(begin, end, _args);
}
