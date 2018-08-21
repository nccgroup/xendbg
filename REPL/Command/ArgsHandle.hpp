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
    using ArgsList = std::vector<std::pair<std::string, std::string>>;

  public:
    void put(const Argument& arg, std::string value) {
      _args.push_back(std::make_pair(arg.get_name(), std::move(value)));
    }

    // TODO: no OOB error handling
    template <typename T, typename F>
    T get(size_t index, F f) const {
      auto s = _args.at(index).first;
      return f(s);
    }

  private:
    ArgsList _args;
  };
}

#endif //XENDBG_ARGSHANDLE_HPP
