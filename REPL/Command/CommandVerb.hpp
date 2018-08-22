//
// Created by Spencer Michaels on 8/21/18.
//

#ifndef XENDBG_COMMANDVERB_HPP
#define XENDBG_COMMANDVERB_HPP

#include "CommandBase.hpp"
#include "Verb.hpp"

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class CommandVerb : public CommandBase {
  public:
    explicit CommandVerb(Verb verb)
        : CommandBase(verb.get_name(), verb.get_description()), _verb(std::move(verb)) {};

    void print(std::ostream& out, xd::util::IndentHelper& indent) const override;

    std::optional <Action> match(const std::string &s) const override;
    std::optional<std::vector<std::string>> complete(
        const std::string& s) const override;

  private:
    Verb _verb;
  };

}

#endif //XENDBG_COMMANDVERB_HPP
