//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <string>

#include "Action.hpp"

namespace xd::repl::cmd {

  class Verb {
  public:
    Verb(std::string name, std::string description)
        : _name(std::move(name)), _description(std::move(description)) {};

    std::string get_name() const { return _name; };

    std::optional<Action> match(std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    const std::string _name;
    const std::string _description;
  };

}

#endif //XENDBG_VERB_HPP
