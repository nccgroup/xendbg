//
// Created by Spencer Michaels on 8/21/18.
//

#ifndef XENDBG_COMMANDBASE_HPP
#define XENDBG_COMMANDBASE_HPP

#include <optional>
#include <string>
#include <vector>

#include "Action.hpp"

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class CommandBase {
  public:
    CommandBase(std::string name, std::string description)
        : _name(std::move(name)), _description(std::move(description)) {};
    virtual ~CommandBase() {};

    std::string get_name() const { return _name; };
    std::string get_description() const { return _description; };

    virtual void print(std::ostream& out, xd::util::IndentHelper& indent) const = 0;

    virtual std::optional<Action> match(std::string::const_iterator begin, std::string::const_iterator end) const = 0;

    virtual std::optional<std::vector<std::string>> complete(std::string::const_iterator begin, std::string::const_iterator end) const = 0;

  private:
    const std::string _name;
    const std::string _description;
  };

}

#endif //XENDBG_COMMANDBASE_HPP
