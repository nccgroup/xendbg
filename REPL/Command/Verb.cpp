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
  auto new_begin = expect(_name, skip_whitespace(begin, end), end);

  if (new_begin == begin)
    return std::nullopt;

  auto [flags, flags_end] = match_flags(new_begin, end);
  auto [args, args_end] = match_args(flags_end, end);

  if (args_end != end)
    throw std::runtime_error("TODO: too many args"); // TODO

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
      throw std::runtime_error("unknown flag!");

    const auto& flag = *matched_flag;

    auto [args, args_end] = match_args(it, end);
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

std::pair<Verb::ArgsHandle, std::string::const_iterator> Verb::match_args(
    std::string::const_iterator begin, std::string::const_iterator end,
    const std::vector<cmd::Argument> &args) const
{
  ArgsHandle args_handle;

  auto it = begin;
  for (const auto& arg : args) {
    it = skip_whitespace(it, end);

    auto arg_end = arg.match(it, end);
    if (arg_end == it)
      throw std::runtime_error("failed to match arg!");

    args_handle.put(arg.get_name(), std::string(it, arg_end));
    it = arg_end;
  }

  return std::make_pair(args_handle, it);
}

