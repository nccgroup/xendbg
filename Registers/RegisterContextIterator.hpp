//
// Created by Spencer Michaels on 9/16/18.
//

#ifndef XENDBG_REGISTERCONTEXTITERATOR_HPP
#define XENDBG_REGISTERCONTEXTITERATOR_HPP

#include <cstddef>

namespace xd::reg {

  template <typename RegisterContext_t>
  class RegisterContextIterator {
  public:
    explicit RegisterContextIterator(RegisterContext_t *context)
      : _context(context), _index(0) {};

    ~RegisterContextIterator() = default;

    RegisterContextIterator(const RegisterContextIterator &it) {
      _context = it._context;
      _index = it._index;
    }

    RegisterContextIterator& operator=(const RegisterContextIterator &it) {
      _context = it._context;
      _index = it._index;
      return *this;
    }

    template <typename Reg_t>
    Reg_t &operator*() {
      return _context->operator[](_index);
    }

    template <typename Reg_t>
    Reg_t &operator->() {
      return _context->operator[](_index);
    }

    RegisterContextIterator operator++() {
      ++_index;
      return *this;
    }

  private:
    RegisterContext_t *_context;
    size_t _index;
  };

}

#endif //XENDBG_REGISTERCONTEXTITERATOR_HPP
