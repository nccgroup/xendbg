//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_INDENT_HELPER_HPP
#define XENDBG_INDENT_HELPER_HPP

#include <cstddef>
#include <ostream>
#include <iostream>

namespace xd::util {

  class IndentHelper {
    public:
      IndentHelper(size_t indent_size = 2, bool use_tabs = false)
        : _indent_size(indent_size), _indent_level(0), _use_tabs(use_tabs) {};

      void indent(size_t i = 1) { _indent_level += i; };
      void unindent(size_t i = 1) { _indent_level -= i; };

      std::string make_indent() const {
        const char c = _use_tabs ? '\t' : ' ';
        if (_indent_level == 0)
          return "";
        return std::string(_indent_level * _indent_size, c);
      };

    private:
      size_t _indent_size, _indent_level;
      bool _use_tabs;
  };

}

std::ostream &operator<<(std::ostream &out, const xd::util::IndentHelper &indent);

#endif //XENDBG_INDENT_HELPER_HPP
