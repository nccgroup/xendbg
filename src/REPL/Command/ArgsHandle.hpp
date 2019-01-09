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

#ifndef XENDBG_ARGSHANDLE_HPP
#define XENDBG_ARGSHANDLE_HPP

#include "Argument.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace xd::repl::cmd {

  class NoSuchArgumentException : public std::runtime_error {
  public:
    NoSuchArgumentException(const std::string &msg)
      : std::runtime_error(msg) {};
  };

  class ArgsHandle {
  private:
    using ArgName = std::string;
    using ArgValue = std::string;
    using ArgsList = std::vector<std::pair<ArgName, ArgValue>>;

  public:
    void put(const Argument& arg, ArgValue value) {
      _args.push_back(std::make_pair(arg.get_name(), std::move(value)));
    }

    bool has(size_t index) const {
      return get_opt(index).has_value();
    }

    bool has(const std::string &name) const {
      return get_opt(name).has_value();
    }

    ArgValue get(size_t index) const {
      auto val = get_opt(index);
      if (!val)
        throw NoSuchArgumentException("index " + std::to_string(index));
      return val.value();
    }

    ArgValue get(const std::string &name) const {
      auto val = get_opt(name);
      if (!val)
        throw NoSuchArgumentException(name);
      return val.value();
    }

    std::optional<ArgValue> get_opt(size_t index) const {
      if (index >= _args.size())
        return std::nullopt;

      return _args.at(index).second;
    }

    std::optional<ArgValue> get_opt(const std::string &name) const {
      auto found = std::find_if(_args.begin(), _args.end(),
          [name](const auto& arg) {
            return arg.first == name;
          });

      if (found == _args.end())
        return std::nullopt;

      return found->second;
    }

  private:
    ArgsList _args;
  };
}

#endif //XENDBG_ARGSHANDLE_HPP
