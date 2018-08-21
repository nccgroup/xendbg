//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "Action.hpp"
#include "Argument.hpp"
#include "ArgsHandle.hpp"
#include "CommandVerb.hpp"
#include "Flag.hpp"
#include "FlagsHandle.hpp"

namespace xd::repl::cmd {

  class Verb {
  private:
    using MakeActionFn = std::function<Action(const FlagsHandle&, const ArgsHandle&)>;

  public:
    Verb(std::string name, std::string description,
        std::vector<Flag> flags, std::vector<Argument> args, MakeActionFn make_action);

    // Convert implicitly to a Command wrapper
    operator CommandVerb() const { return CommandVerb(*this); };

    void add_arg(Argument arg);

    std::string get_name() const { return _name; };
    std::string get_description() const { return _description; };

    std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const;

  private:
    std::pair<std::string::const_iterator, FlagsHandle> match_flags(
        std::string::const_iterator begin, std::string::const_iterator end) const;
    std::pair<std::string::const_iterator, ArgsHandle> match_args(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    const std::string _name;
    const std::string _description;
    std::vector<Flag> _flags;
    std::vector<Argument> _args;
    MakeActionFn _make_action;
  };

}

#endif //XENDBG_VERB_HPP
