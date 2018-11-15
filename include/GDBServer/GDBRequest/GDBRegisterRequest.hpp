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

  class GeneralRegistersBatchReadRequest : public GDBRequestBase {
  public:
    explicit GeneralRegistersBatchReadRequest(const std::string &data);

    size_t get_thread_id() const { return _thread_id; };

  private:
    size_t _thread_id;
  };

  class RegisterReadRequest : public GDBRequestBase {
  public:
    explicit RegisterReadRequest(const std::string &data);

    uint16_t get_register_id() const { return _register_id; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    size_t _thread_id;
  };

  class RegisterWriteRequest : public GDBRequestBase {
  public:
    explicit RegisterWriteRequest(const std::string &data);

    uint16_t get_register_id() const { return _register_id; };
    uint64_t get_value() const { return _value; };
    size_t get_thread_id() const { return _thread_id; };

  private:
    uint16_t _register_id;
    uint64_t _value;
    size_t _thread_id;
  };

  class GeneralRegistersBatchWriteRequest : public GDBRequestBase {
  private:
    using Value = std::variant<uint64_t, uint32_t, uint16_t, uint8_t>;
    using Values =  std::vector<std::pair<size_t, Value>>;

  public:
    explicit GeneralRegistersBatchWriteRequest(const std::string &data);

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
