//
// Created by Spencer Michaels on 8/16/18.
//

#ifndef XENDBG_TOKENMATCHRESULT_HPP
#define XENDBG_TOKENMATCHRESULT_HPP

#include <optional>
#include <string>
#include <utility>

namespace xd::parser::token {

  template<typename Token_t>
  using TokenMatchResult = std::pair<std::optional<Token_t>, std::string::const_iterator>;

}

#endif //XENDBG_TOKENMATCHRESULT_HPP
