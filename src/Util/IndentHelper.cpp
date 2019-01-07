#include <Util/IndentHelper.hpp>

std::ostream &operator<<(std::ostream &out, const xd::util::IndentHelper &indent) {
  out << indent.make_indent();
  return out;
}
