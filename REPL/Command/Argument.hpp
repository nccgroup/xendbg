//
// Created by Spencer Michaels on 8/20/18.
//

#ifndef XENDBG_ARGUMENT_HPP
#define XENDBG_ARGUMENT_HPP

#include <functional>
#include <string>

#include "../../Util/string.hpp"

namespace xd::repl::cmd {

  class Argument {
  public:
    using MatcherFn = std::function<std::string::const_iterator(
        std::string::const_iterator, std::string::const_iterator)>;

    Argument(std::string name, std::string description, MatcherFn matcher)
        : _name(std::move(name)), _description(std::move(description)), _matcher(std::move(matcher)) {};

    const std::string& get_name() const { return _name; };
    const std::string& get_description() const { return _description; };

    virtual std::string::const_iterator match(
        std::string::const_iterator begin, std::string::const_iterator end) const {
      return _matcher(begin, end);
    };

  private:
    std::string _name;
    std::string _description;
    MatcherFn _matcher;
  };

}

#endif //XENDBG_ARGUMENT_HPP
