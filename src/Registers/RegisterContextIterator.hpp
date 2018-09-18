//
// Created by Spencer Michaels on 9/16/18.
//

#ifndef XENDBG_REGISTERCONTEXTITERATOR_HPP
#define XENDBG_REGISTERCONTEXTITERATOR_HPP

#include <cstddef>

#include "../Util/choice.hpp"

namespace xd::reg {

  template <typename RegisterContext_t, bool is_const>
  class _RegisterContextIterator {
  private:
     using Pointer = typename util::choice<is_const,
           RegisterContext_t const *, RegisterContext_t *>::type;

     template <typename Reg_t>
     using Register = typename util::choice<is_const, const Reg_t, Reg_t>::type;

  public:
    explicit _RegisterContextIterator(Pointer context, size_t index = 0)
      : _context(context), _index(index) {};

    ~_RegisterContextIterator() = default;

    _RegisterContextIterator(const _RegisterContextIterator &it) {
      _context = it._context;
      _index = it._index;
    }

    _RegisterContextIterator& operator=(const _RegisterContextIterator &it) {
      _context = it._context;
      _index = it._index;
      return *this;
    }

    template <typename Reg_t>
    Reg_t &operator*() const {
      return _context->template operator[]<Reg_t>(_index);
    }

    _RegisterContextIterator operator++() {
      ++_index;
      return *this;
    }

    bool operator!=(const _RegisterContextIterator &it) const {
      return _context != it._context ||
        _index != it._index;
    }

    bool operator==(const _RegisterContextIterator &it) const {
      return _context == it._context &&
        _index == it._index;
    }

  private:
    RegisterContext_t *_context;
    size_t _index;
  };

  template <typename RegisterContext_t>
  using RegisterContextIterator = _RegisterContextIterator<RegisterContext_t, false>;

  template <typename RegisterContext_t>
  using RegisterContextConstIterator = _RegisterContextIterator<RegisterContext_t, true>;

}

#endif //XENDBG_REGISTERCONTEXTITERATOR_HPP
