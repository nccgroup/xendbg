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

std::optional<Action> CommandVerb::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  return _verb.match(begin, end);
}

std::optional<std::vector<std::string>> CommandVerb::complete(std::string::const_iterator begin, std::string::const_iterator end) const
{
  return _verb.complete(begin, end);
}
