#include "MakeCommand.hpp"

using xd::repl::cmd::Command;
using xd::repl::cmd::CommandBase;
using xd::repl::cmd::CommandVerb;
using xd::repl::cmd::Verb;

std::unique_ptr<CommandBase> xd::repl::cmd::make_command(Verb verb) {
  return std::make_unique<CommandVerb>(verb);
}

std::unique_ptr<CommandBase> xd::repl::cmd::make_command(
    std::string name, std::string description, std::vector<Verb> verbs)
{
  return std::make_unique<Command>(name, description, verbs);
}
