//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTER_CONTEXT_HPP
#define XENDBG_REGISTER_CONTEXT_HPP

#include <string>

namespace reg {
  template <typename Context_t, typename Reg_t, bool matches>
  struct __offset_of_impl;

  template <typename Context_t, typename Reg_t>
  struct __offset_of_impl<Context_t, Reg_t, true> {
    static constexpr auto offset = Context_t::base;
  };

  template <typename Context_t, typename Reg_t>
  struct __offset_of_impl<Context_t, Reg_t, false> {
    static constexpr auto offset = Context_t::Next::template offset_of<Reg_t>;
  };

  template <typename Context_t, typename Reg_t>
  struct _offset_of_impl : public __offset_of_impl<
    Context_t, Reg_t, std::is_same<
      typename Context_t::Register,
      Reg_t>::value>
  {};

  template <typename Reg_t>
  struct _offset_of_error_impl {
    static_assert(std::is_same<Reg_t, void>::value, "No such register!");
  };

  template <size_t base, typename... Registers_t>
  class _RegisterContext;

  template <size_t _base>
  class _RegisterContext<_base> {
  public:
    static constexpr auto base = _base;

    template <typename F>
    void for_each(F) {};

    template <typename Reg_t>
    static constexpr auto offset_of =
      _offset_of_error_impl<Reg_t>::offset;
  };

  template <size_t _base, typename Register_t, typename... Registers_t>
  class _RegisterContext<_base, Register_t, Registers_t...>
    : public _RegisterContext<
        _base+sizeof(typename Register_t::Value),
        Registers_t...>
  {
  protected:
    template <typename Context_t, typename Reg_t>
    friend struct _offset_of_impl;
    template <typename Context_t, typename Reg_t, bool matches>
    friend struct __offset_of_impl;

    using This = _RegisterContext<_base, Register_t, Registers_t...>;
    using Next = _RegisterContext<
          _base+sizeof(typename Register_t::Value),
          Registers_t...>;
    using Register = Register_t;

  public:
    static constexpr auto base = _base;

    struct RegisterMetadataReference {
      const size_t &offset;
      const decltype(Register_t::name) &name;
      const decltype(Register_t::alt_name) &alt_name;
    };

    template <typename Reg_t>
    static constexpr auto offset_of =
      _offset_of_impl<This, Reg_t>::offset;

    template <typename Reg_t>
    Reg_t get() {
      if constexpr (std::is_same<Reg_t, Register_t>::value)
        return _register;
      else
        return Next::get();
    };

    template <typename F>
    void for_each(F f) {
      RegisterMetadataReference metadata = {
        offset_of<Register_t>,
        Register_t::name,
        Register_t::alt_name,
      };

      f(metadata, _register);

      Next::template for_each(f);
    };

  private:
    Register_t _register;
  };

  template <typename... Registers_t>
  using RegisterContext = _RegisterContext<0, Registers_t...>;

}

#endif //XENDBG_REGISTER_CONTEXT_HPP
