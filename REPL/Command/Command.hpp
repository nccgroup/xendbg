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
    Command(std::string name, std::string description)
        : _name(std::move(name)), _description(std::move(description)) {};

    std::string get_name() const { return _name; };
    std::optional<Action> match(std::string::const_iterator begin, std::string::const_iterator end) const;

    void add_verb(const Verb& verb) { _verbs.push_back(verb); }

  private:
    const std::string _name;
    const std::string _description;
    std::vector<Verb> _verbs;
  };

}

#endif //XENDBG_COMMAND_HPP
