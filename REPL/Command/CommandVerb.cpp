//
// Created by Spencer Michaels on 8/21/18.
//

#include "CommandVerb.hpp"
#include "../../Util/IndentHelper.hpp"

using xd::repl::cmd::Action;
using xd::repl::cmd::CommandVerb;
using xd::util::IndentHelper;

void CommandVerb::print(std::ostream& out, IndentHelper& indent) const {
  _verb.print(out, indent);
}

std::optional<Action> CommandVerb::match(const std::string& s) const {
  auto action = _verb.match(s.begin(), s.end());
  if (action)
    return action;

  return std::nullopt;
}

std::optional<std::vector<std::string>> CommandVerb::complete(
    const std::string& s) const
{
  return _verb.complete(s.begin(), s.end());
}
