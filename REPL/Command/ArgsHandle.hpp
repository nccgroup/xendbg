//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_ARGSHANDLE_HPP
#define XENDBG_ARGSHANDLE_HPP

#include "Argument.hpp"

#include <string>
#include <utility>
#include <vector>

namespace xd::repl::cmd {

  class ArgsHandle {
  private:
    using ArgName = std::string;
    using ArgValue = std::string;
    using ArgsList = std::vector<std::pair<ArgName, ArgValue>>;

  public:
    void put(const Argument& arg, ArgValue value) {
      _args.push_back(std::make_pair(arg.get_name(), std::move(value)));
    }

    std::string get(size_t index) const {
      if (index >= _args.size())
        throw std::runtime_error("No such argument!");

      return _args.at(index).second;
    }

    std::string get(const std::string &name) const {
      auto found = std::find_if(_args.begin(), _args.end(),
          [name](const auto& arg) {
            return arg.first == name;
          });

      return found->second;
    }

  private:
    ArgsList _args;
  };
}

#endif //XENDBG_ARGSHANDLE_HPP
