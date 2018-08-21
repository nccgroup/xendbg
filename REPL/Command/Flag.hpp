//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_FLAG_HPP
#define XENDBG_FLAG_HPP

#include <string>
#include <vector>

#include "Argument.hpp"
#include "ArgsHandle.hpp"

namespace xd::repl::cmd {

  class Flag {
  public:
    Flag(char short_name, std::string long_name, std::string description,
        std::vector<Argument> args);

    void add_arg(Argument arg);

    char get_short_name() const { return _short_name; };
    const std::string& get_long_name() const { return _long_name; };
    const std::string& get_description() const { return _description; };

    std::pair<std::string::const_iterator, ArgsHandle> match(
        std::string::const_iterator begin, std::string::const_iterator end) const;

  private:
    const char _short_name;
    const std::string _long_name;
    const std::string _description;
    std::vector<Argument> _args;
  };

}

#endif //XENDBG_FLAG_HPP
