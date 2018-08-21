//
// Created by Spencer Michaels on 8/19/18.
//

#include "Verb.hpp"
#include "../../Util/string.hpp"

#include <iostream>

using xd::util::string::expect;
using xd::util::string::next_whitespace;
using xd::util::string::skip_whitespace;

using xd::repl::cmd::Action;
using xd::repl::cmd::Verb;

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

std::pair<Verb::FlagsHandle, std::string::const_iterator> Verb::match_flags(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  FlagsHandle flags_handle;

  auto it = skip_whitespace(begin, end);
  auto matched_flag = _flags.end();
  while (it != end && *it == '-') {
    for (auto flag_it = _flags.begin(); flag_it != _flags.end(); ++flag_it) {
      auto match_pos = flag_it->match(it, end);
      if (match_pos != it) {
        matched_flag = flag_it;
        it = match_pos;
        break;
      }
    }

    if (matched_flag == _flags.end())
      throw std::runtime_error("Unknown flag!");

    const auto& flag = *matched_flag;

    auto [args, args_end] = match_args(it, end); // TODO: use the other match_args
    flags_handle.put(flag, args);

    it = skip_whitespace(args_end, end);
  }

  return std::make_pair(flags_handle, it);
}

std::pair<Verb::ArgsHandle, std::string::const_iterator> Verb::match_args(
    std::string::const_iterator begin, std::string::const_iterator end) const
{
  return match_args(begin, end, _args);
}

