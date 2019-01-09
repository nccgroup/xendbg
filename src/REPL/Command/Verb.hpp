//
// Copyright (C) 2018-2019 Spencer Michaels
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "Action.hpp"
#include "Argument.hpp"
#include "ArgsHandle.hpp"
#include "Flag.hpp"
#include "FlagsHandle.hpp"

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class ExtraArgumentException : public std::runtime_error {
  public:
    ExtraArgumentException(const std::string &msg)
      : std::runtime_error(msg) {};
  };

  class Verb {
  public:
    using MakeActionFn = std::function<Action(const FlagsHandle&, const ArgsHandle&)>;

    Verb(std::string name, std::string description,
        std::vector<Flag> flags, std::vector<Argument> args, MakeActionFn make_action);

    void print(std::ostream& out, xd::util::IndentHelper& indent) const;

    void add_arg(Argument arg);

    std::string get_name() const { return _name; };
    std::string get_description() const { return _description; };

    std::string::const_iterator match_name(std::string::const_iterator begin, std::string::const_iterator end) const;
    std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const;
    std::optional<std::vector<std::string>> complete(
        std::string::const_iterator begin, std::string::const_iterator end) const;

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
