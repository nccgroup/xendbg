//
// Created by Spencer Michaels on 10/1/18.
//

#ifndef XENDBG_GDBREGISTERREQUEST_HPP
#define XENDBG_GDBREGISTERREQUEST_HPP

#include <variant>
#include <vector>

#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>

#include "GDBRequestBase.hpp"

namespace xd::gdb::req {

  class RegisterReadRequest : public GDBRequestBase {
  public:
    explicit RegisterReadRequest(const std::string &data)
      : GDBRequestBase(data, 'p')
    {
      _register_id = read_hex_number<uint16_t>();
      if (check_char(';')) {
        expect_string("thread:");
        _thread_id = read_hex_number<size_t>();
        expect_char(';');
      } else {
        _thread_id = (size_t)-1;
      }
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    size_t _thread_id;
  };

  class RegisterWriteRequest : public GDBRequestBase {
  public:
    explicit RegisterWriteRequest(const std::string &data)
      : GDBRequestBase(data, 'P')
    {
      _register_id = read_hex_number<uint16_t>();
      expect_char('=');
      _value = read_hex_number_respecting_endianness<uint64_t>();
      if (check_char(';')) {
        expect_string("thread:");
        _thread_id = read_hex_number<size_t>();
        expect_char(';');
      }
      expect_end();
    };

    uint16_t get_register_id() const { return _register_id; };
    uint64_t get_value() const { return _value; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    uint64_t _value;
    size_t _thread_id;
  };

  DECLARE_SIMPLE_REQUEST(GeneralRegistersBatchReadRequest, 'g');

  class GeneralRegistersBatchWriteRequest : public GDBRequestBase {
  private:
    using Value = std::variant<uint64_t, uint32_t, uint16_t, uint8_t>;
    using Values =  std::vector<std::pair<size_t, Value>>;

  public:
    explicit GeneralRegistersBatchWriteRequest(const std::string &data)
      : GDBRequestBase(data, 'g')
    {
      using Regs64 = xd::reg::x86_64::RegistersX86_64;
      using Regs32 = xd::reg::x86_32::RegistersX86_32;

      size_t index = 0;
      const auto size = get_num_remaining()/2;

      if (size == Regs64::size) {
        Regs64::for_each_metadata([this, &index](const auto md) {
          const auto word = read_word(md);
          if (word)
            _values.push_back(std::make_pair(index, *word));
          ++index;
        });
      } else if (size == Regs32::size) {
        Regs32::for_each_metadata([this, &index](const auto md) {
          const auto word = read_word(md);
          if (word)
            _values.push_back(std::make_pair(index, *word));
          ++index;
        });
      } else {
        throw RequestPacketParseException("Invalid register packet size");
      }
      expect_end();
    };

    const Values& get_values() const { return _values; };

  private:
    Values _values;

    template <typename Metadata_t>
    std::optional<typename Metadata_t::Register::Value> read_word(
        const Metadata_t&)
    {
      using RegisterValue = typename Metadata_t::Register::Value;
      return read_word_unsigned_opt<RegisterValue>();
    }
  };

}

#endif //XENDBG_GDBREGISTERREQUEST_HPP
