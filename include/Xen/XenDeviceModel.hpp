//
// Created by Spencer Michaels on 10/2/18.
//

#ifndef XENDBG_XENDEVICEMODEL_HPP
#define XENDBG_XENDEVICEMODEL_HPP

#include "BridgeHeaders/xendevicemodel.h"
#include "Common.hpp"

namespace xd::xen {

  class Domain;

  class XenDeviceModel {
  public:
    XenDeviceModel();

    xendevicemodel_handle *get() { return _xendevicemodel.get(); };

    void inject_event(const Domain &domain, VCPU_ID vcpu_id, uint8_t vector,
        uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2);

  private:
    std::unique_ptr<xendevicemodel_handle,
      decltype(&xendevicemodel_close)> _xendevicemodel;

  };

}

#endif //XENDBG_XENDEVICEMODEL_HPP
