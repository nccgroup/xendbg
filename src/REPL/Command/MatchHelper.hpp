//
// Created by Spencer Michaels on 8/29/18.
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
