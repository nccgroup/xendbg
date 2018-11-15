//
// Created by Spencer Michaels on 10/1/18.
//

#include <GDBServer/GDBRequest/GDBQueryRequest.hpp>

using namespace xd::gdb::req;

QueryWatchpointSupportInfo::QueryWatchpointSupportInfo(const std::string &data)
  : GDBRequestBase(data, "qWatchpointSupportInfo")
{
  check_char(':');
  expect_end();
};

QuerySupportedRequest::QuerySupportedRequest(const std::string &data)
  : GDBRequestBase(data, "qSupported")
{
  expect_char(':');
  while (has_more()) {
    const auto feature = read_until_char_or_end(';');
    _features.push_back(feature);
  }
  expect_end();
};

QueryRegisterInfoRequest::QueryRegisterInfoRequest(const std::string &data)
  : GDBRequestBase(data, "qRegisterInfo")
{
  _register_id = read_hex_number<uint16_t>();
  expect_end();
};

QueryMemoryRegionInfoRequest::QueryMemoryRegionInfoRequest(const std::string &data)
  : GDBRequestBase(data, "qMemoryRegionInfo")
{
  expect_char(':');
  _address = read_hex_number<uint64_t>();
  expect_end();
};
