//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_COMMAND_HPP
#define XENDBG_COMMAND_HPP

#include <optional>
#include <string>
#include <vector>

#include "Action.hpp"
#include "Verb.hpp"

namespace xd::repl::cmd {

  class Command {
  public:
    Command(std::string name, std::string description, std::vector<Verb> verbs)
        : _name(std::move(name)), _description(std::move(description)), _verbs(std::move(verbs)) {};

    std::string get_name() const { return _name; };
    std::optional<Action> match(const std::string& s) const;

    void add_verb(const Verb& verb) { _verbs.push_back(verb); }

  private:
    const std::string _name;
    const std::string _description;
    std::vector<Verb> _verbs;
  };

}

#endif //XENDBG_COMMAND_HPP
