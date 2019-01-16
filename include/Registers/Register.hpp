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

#ifndef XENDBG_REGISTER_HPP
#define XENDBG_REGISTER_HPP

#include <cstddef>
#include <cstdint>
#include <iostream>

namespace xd::reg {

  template <typename Value_t, size_t width>
  class _Register_impl;

  template <typename Value_t>
  class _Register_impl<Value_t, 2> {
  public:
    _Register_impl(Value_t &value)
      : _value(value) {};

    uint8_t get8h() const {
      return (this->_value >> 0x8) & 0xFF;
    };
    void set8h(uint8_t new_value) {
      this->_value &= ~0xFF00;
      this->_value |= (Value_t)new_value << 0x8;
    };

    uint8_t get8l() const {
      return this->_value & 0xFF;
    };
    void set8l(uint8_t new_value) {
      this->_value &= ~0xFF;
      this->_value |= (Value_t)new_value;
    };

    uint16_t get16() const {
      return this->_value & 0xFFFF;
    };
    void set16(uint16_t new_value) {
      this->_value &= ~0xFFFF;
      this->_value |= new_value;
    };

  private:
    Value_t& _value;
  };

  template <typename Value_t>
  class _Register_impl<Value_t, 4> : public _Register_impl<Value_t, 2> {
  public:
    _Register_impl(Value_t &value)
      : _Register_impl<Value_t, 2>(value), _value(value) {};

    uint32_t get32() const {
      return this->_value & 0xFFFFFFFFUL;
    };
    void set32(uint32_t new_value) {
      this->_value &= ~0xFFFFFFFFUL;
      this->_value |= new_value;
    };

  private:
    Value_t& _value;
  };

  template <typename Value_t>
  class _Register_impl<Value_t, 8> : public _Register_impl<Value_t, 4> {
  public:
    _Register_impl(Value_t &value)
      : _Register_impl<Value_t, 4>(value), _value(value) {};

    uint64_t get64() const {
      return this->_value;
    };
    void set64(uint64_t new_value) {
      this->_value |= new_value;
    };

  private:
    Value_t& _value;
  };

  template <typename Value_t>
  struct Register : _Register_impl<Value_t, sizeof(Value_t)> {
  public:
    using Value = Value_t;

    Register()
      : _Register_impl<Value_t, sizeof(Value_t)>(_value)
    {
    };

    Register(Value_t value)
      : _Register_impl<Value_t, sizeof(Value_t)>(_value), _value(value)
    {
    };

    void clear() { _value = 0; };

    Register &operator=(const Register &other) {
      _value = (Value_t)other;
      return *this;
    };

    operator Value_t() const {
      return (Value_t)_value;
    }

    Register &operator-=(Value_t value) {
      _value -= value;
      return *this;
    }

    Register &operator+=(Value_t value) {
      _value += value;
      return *this;
    }

    Register &operator|=(Value_t value) {
      _value |= value;
      return *this;
    }

    Register &operator&=(Value_t value) {
      _value &= value;
      return *this;
    }

  private:
    Value_t _value;
  };

}

#define DECLARE_REGISTER_ALTNAME(_name, _alt_name, _type, _gcc_id) \
  struct _name : public xd::reg::Register<_type> { \
    _name() : xd::reg::Register<_type>() {}; \
    _name(_type value) : xd::reg::Register<_type>(value) {}; \
    static constexpr auto name = #_name; \
    static constexpr auto alt_name = #_alt_name; \
    static constexpr size_t gcc_id = _gcc_id; \
}

#define DECLARE_REGISTER(_name, _type, _gcc_id) \
  DECLARE_REGISTER_ALTNAME(_name, nullptr, _type, _gcc_id)

#endif //XENDBG_REGISTER_HPP
