//
// Created by Spencer Michaels on 9/10/18.
//

#ifndef XENDBG_REGISTERS_HPP
#define XENDBG_REGISTERS_HPP

#include <cstddef>
#include <cstdint>

namespace reg {

  template <typename Value_t, size_t width>
  class _Register_impl;

  template <typename Value_t>
  class _Register_impl<Value_t, 0> {
  protected:
    _Register_impl(Value_t &value)
      : _value(value) {};

    Value_t& _value;
  };

  template <typename Value_t>
  class _Register_impl<Value_t, 2> : public _Register_impl<Value_t, 0> {
  public:
    _Register_impl(Value_t &value)
      : _Register_impl<Value_t, 0>(value) {};

    uint8_t get8_upper() const {
      return (this->_value >> 0x8) & 0xFF;
    };
    void set8_upper(uint8_t new_value) {
      this->_value &= ~0xFF00;
      this->_value |= (Value_t)new_value << 0x8;
    };

    uint8_t get8_lower() const {
      return this->_value & 0xFF;
    };
    void set8_lower(uint8_t new_value) {
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

    operator uint8_t() const {
      return this->get8_lower();
    };
    operator uint16_t() const {
      return this->get16();
    };
  };

  template <typename Value_t>
  class _Register_impl<Value_t, 4> : public _Register_impl<Value_t, 2> {
  public:
    _Register_impl(Value_t &value)
      : _Register_impl<Value_t, 2>(value), _value(value) {};

    uint32_t get32() const {
      return this->_value & 0xFFFFFFFF;
    };
    void set32(uint32_t new_value) {
      this->_value &= ~0xFFFFFFFF;
      this->_value |= new_value;
    };

    operator uint32_t() const {
      return this->get32();
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
      return this->_value & 0xFFFFFFFFFFFFFFFF;
    };
    void set64(uint64_t new_value) {
      this->_value &= ~0xFFFFFFFFFFFFFFFF;
      this->_value |= new_value;
    };

    operator uint64_t() const {
      return this->get64();
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
    {};
    Register(Value_t value)
      : _value(value), _Register_impl<Value_t, sizeof(Value_t)>(_value)
    {};

    void clear() { _value = 0; };

    Register &operator=(const Register &other) {
      _value = other;
      return *this;
    };

  private:
    Value_t _value;
  };

}

#define DECLARE_REGISTER_ALTNAME(_name, _alt_name, _type) \
  struct _name : public reg::Register<_type> { \
    _name() : reg::Register<_type>() {}; \
    _name(_type value) : reg::Register<_type>(value) {}; \
    static constexpr auto name = #_name; \
    static constexpr auto alt_name = #_alt_name; \
}

#define DECLARE_REGISTER(_name, _type) \
  DECLARE_REGISTER_ALTNAME(_name, nullptr, _type)

#endif //XENDBG_REGISTERS_HPP
