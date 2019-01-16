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

#ifndef XENDBG_MATCHHELPER_HPP
#define XENDBG_MATCHHELPER_HPP

#include <functional>
#include <string>
#include <vector>

#include <Util/string.hpp>

namespace xd::repl::cmd::match {

  template <typename It_t>
  using MatcherFn = std::function<It_t(It_t, It_t)>;

  template <typename It_t>
  It_t match_everything(It_t /*begin*/, It_t end) {
    return end;
  }

  template <typename It_t>
  It_t match_word(It_t begin, It_t end) {
    return util::string::next_whitespace(begin, end);
  }

  template <typename It_t>
  It_t match_number_unsigned(It_t begin, It_t end) {
    const auto ws = util::string::next_whitespace(begin, end);

    try {
      std::stoul(std::string(begin, ws));
      return ws;
    } catch (const std::invalid_argument &e) {
      return begin;
    }
  }

  template <typename It_t, typename Container_t>
  MatcherFn<It_t> make_match_one_of(Container_t options) {
    return [options](It_t begin, It_t end) {
      size_t len = 0;
      std::find_if(options.begin(), options.end(),
          [begin, end, &len](const auto& opt) {
            if (util::string::is_prefix(opt.begin(), opt.end(), begin, end)) {
              len = opt.size();
              return true;
            }
            return false;
          });

      return begin + len;
    };
  }

}

#endif //XENDBG_MATCHHELPER_HPP
