//
// Created by Spencer Michaels on 8/21/18.
//

#ifndef XENDBG_MAKECOMMAND_HPP
#define XENDBG_MAKECOMMAND_HPP

#include <memory>

#include "Command.hpp"
#include "CommandBase.hpp"
#include "CommandVerb.hpp"
#include "Verb.hpp"

namespace xd::repl::cmd {

  std::unique_ptr<CommandBase> make_command(Verb verb);
  std::unique_ptr<CommandBase> make_command(
      std::string name, std::string description, std::vector<Verb> verbs);

}

#endif //XENDBG_MAKECOMMAND_HPP
