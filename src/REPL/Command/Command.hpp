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
