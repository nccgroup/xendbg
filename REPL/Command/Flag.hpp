//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_FLAG_HPP
#define XENDBG_FLAG_HPP

#include <string>
#include <vector>

#include "Argument.hpp"

namespace xd::repl::cmd {

  class Flag {
  public:
    Flag(char short_name, std::string long_name, std::string description,
        std::vector<Argument> args)
      : _short_name(short_name), _long_name(std::move(long_name)),
        _description(std::move(description)), _args(std::move(args)) {};

    char get_short_name() const { return _short_name; };
    const std::string& get_long_name() const { return _long_name; };
    const std::string& get_description() const { return _description; };

    std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    char _short_name;
    std::string _long_name;
    std::string _description;
    std::vector<Argument> _args;
  };

}

#endif //XENDBG_FLAG_HPP
