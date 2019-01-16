//
// Copyright (C) 2018-2019 NCC Group
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

#ifndef XENDBG_TOKEN_MATCH_HPP
#define XENDBG_TOKEN_MATCH_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>
#include <variant>

#include "Constant.hpp"
#include "Label.hpp"
#include "Symbol.hpp"
#include "TokenMatchResult.hpp"
#include "Variable.hpp"

namespace xd::parser::token {

  template <typename Token_t, typename... Tokens_t>
  struct _match_tokens_impl;

  template <typename Token_t, typename Tokens_t_first, typename... Tokens_t>
  struct _match_tokens_impl<Token_t, Tokens_t_first, Tokens_t...> {
    static TokenMatchResult<Token_t> match(
        std::string::const_iterator begin, std::string::const_iterator end)
    {
      auto result = Tokens_t_first::match(begin, end);

      if (result.first)
        return result;

      else return _match_tokens_impl<Token_t, Tokens_t...>::match(begin, end);
    }
  };

  template <typename Token_t>
  struct _match_tokens_impl<Token_t> {
    static TokenMatchResult<Token_t> match(
        std::string::const_iterator begin, std::string::const_iterator end)
    {
      return std::make_pair(std::nullopt, begin);
    }
  };

  template <typename... Tokens_t>
  TokenMatchResult<std::variant<Tokens_t...>> match_tokens(
      std::string::const_iterator begin, std::string::const_iterator end)
  {
    using Token = std::variant<Tokens_t...>;
    return _match_tokens_impl<Token, Tokens_t...>::match(begin, end);
  }

}

#endif //XENDBG_TOKEN_MATCH_HPP
