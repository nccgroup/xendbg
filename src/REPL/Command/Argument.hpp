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
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_ARGUMENT_HPP
#define XENDBG_ARGUMENT_HPP

#include <functional>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace xd::util {

  class IndentHelper;

}

namespace xd::repl::cmd {

  class Argument {
  public:
    using CompletionOptions = std::optional<std::vector<std::string>>;
    using CompleterFn = std::function<CompletionOptions(
        std::string::const_iterator, std::string::const_iterator)>;
    using MatcherFn = std::function<std::string::const_iterator(
        std::string::const_iterator, std::string::const_iterator)>;

    Argument(std::string name, std::string description,
             MatcherFn matcher, CompleterFn completer = {})
        : _name(std::move(name)),
          _description(std::move(description)),
          _matcher(std::move(matcher)),
          _completer(completer),
          _is_optional(false) {};

    Argument(std::string name, std::string description,
             MatcherFn matcher, std::string default_value,
             CompleterFn completer = {})
        : _name(std::move(name)),
          _description(std::move(description)),
          _matcher(std::move(matcher)),
          _completer(completer),
          _default_value(std::move(default_value)),
          _is_optional(true) {};

    void print(std::ostream& out, xd::util::IndentHelper& indent) const;

    const std::string& get_name() const { return _name; };
    const std::string& get_description() const { return _description; };
    const std::string& get_default_value() const { return _default_value; };
    bool is_optional() const { return _is_optional; };

    virtual std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const {
      return _matcher(begin, end);
    };

    virtual CompletionOptions complete(
        std::string::const_iterator begin, std::string::const_iterator end) const {
      if (_completer)
        return _completer(begin, end);
      return std::nullopt;
    }

  private:
    const std::string _name;
    const std::string _description;
    const MatcherFn _matcher;
    const CompleterFn _completer;
    const std::string _default_value;
    const bool _is_optional;
  };

}

#endif //XENDBG_ARGUMENT_HPP
