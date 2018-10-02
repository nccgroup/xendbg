#include <Xen/Domain.hpp>
#include <Xen/XenDeviceModel.hpp>
#include <Xen/XenException.hpp>

using xd::xen::Domain;
using xd::xen::VCPU_ID;
using xd::xen::XenDeviceModel;
using xd::xen::XenException;

XenDeviceModel::XenDeviceModel()
  : _xendevicemodel(xendevicemodel_open(nullptr, 0), xendevicemodel_close)
{
}

void XenDeviceModel::inject_event(const Domain &domain, VCPU_ID vcpu_id,
    uint8_t vector, uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2)
{
  int err = xendevicemodel_inject_event(
      _xendevicemodel.get(), domain.get_domid(), vcpu_id,
      vector, type, error_code, insn_len, cr2);

  if (err < 0)
    throw XenException("Failed to inject event!");
}
