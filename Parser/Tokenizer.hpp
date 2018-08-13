//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKENIZER_HPP
#define XENDBG_TOKENIZER_HPP

#include <iostream>
#include <string>
#include <vector>

#include "ParserException.hpp"
#include "Token/Constant.hpp"
#include "Token/Label.hpp"
#include "Token/Match.hpp"
#include "Token/Symbol.hpp"
#include "Token/Variable.hpp"

namespace xd::parser::tokenizer {

  template <typename Container_token, typename Container_pos>
  void tokenize(const std::string& input, Container_token& tokens, Container_pos& tokens_pos) {

    static const auto skip_whitespace = [](auto begin, auto end) {
      return std::find_if_not(begin, end, std::iswspace);
    };

    auto pos = input.begin();
    const auto end = input.end();

    if (pos == end)
      return;

    pos = skip_whitespace(pos, end);
    while (pos != end) {
      auto [tok, new_pos] =
          token::match_tokens<
            token::Constant,
            token::Label,
            token::Symbol,
            token::Variable>(pos, end);
      if (!tok)
        throw except::InvalidInputException(input, new_pos - input.begin());
      tokens.push(*tok);
      tokens_pos.push(pos - input.begin());
      pos = skip_whitespace(new_pos, end);
    }
  }

}

#endif //XENDBG_TOKENIZER_HPP
