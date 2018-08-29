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
        throw std::runtime_error("No such argument!");
      return val.value();
    }

    ArgValue get(const std::string &name) const {
      auto val = get_opt(name);
      if (!val)
        throw std::runtime_error("No such argument!");
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
