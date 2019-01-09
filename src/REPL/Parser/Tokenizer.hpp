//
// Copyright (C) 2018-2019 Spencer Michaels
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
#include <Util/string.hpp>

namespace xd::parser::tokenizer {

  template <typename Container_token, typename Container_pos>
  void tokenize(const std::string& input, Container_token& tokens, Container_pos& tokens_pos) {
    auto pos = input.begin();
    const auto end = input.end();

    if (pos == end)
      return;

    pos = xd::util::string::skip_whitespace(pos, end);
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
      pos = xd::util::string::skip_whitespace(new_pos, end);
    }
  }

}

#endif //XENDBG_TOKENIZER_HPP
