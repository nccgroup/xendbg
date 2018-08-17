//
// Created by Spencer Michaels on 8/12/18.
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
      return std::make_pair(std::optional<Token_t>(), begin);
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
