//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_COMMAND_HPP
#define XENDBG_COMMAND_HPP

#include "CommandBase.hpp"
#include "Verb.hpp"

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class Command : public CommandBase {
  public:
    Command(std::string name, std::string description, std::vector<Verb> verbs)
        : CommandBase(std::move(name), std::move(description)),
          _verbs(std::move(verbs)) {};

    void print(std::ostream& out, xd::util::IndentHelper& indent) const override;

    std::optional<Action> match(std::string::const_iterator begin, std::string::const_iterator end) const override;
    std::optional<std::vector<std::string>> complete(std::string::const_iterator begin, std::string::const_iterator end) const override;

    void add_verb(const Verb& verb) { _verbs.push_back(verb); }

  private:
    std::string::const_iterator match_prefix_skipping_whitespace(
        std::string::const_iterator begin, std::string::const_iterator end) const;

    std::vector<Verb> _verbs;
  };

}

#endif //XENDBG_COMMAND_HPP
