//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_TOKEN_LABEL_HPP
#define XENDBG_TOKEN_LABEL_HPP

#include <string>

namespace xd::parser::token {

  class Label {
  public:
    explicit Label(std::string name)
        : _name(std::move(name)) {}

    std::string name() const { return _name; };

  private:
    std::string _name;
  };
}

#endif //XENDBG_TOKEN_LABEL_HPP
