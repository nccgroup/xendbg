//
// Created by smichaels on 10/19/18.
//

#ifndef XENDBG_XEN_HPP
#define XENDBG_XEN_HPP

#include <memory>
#include <vector>

#include "DomainHVM.hpp"
#include "DomainPV.hpp"
#include "XenCall.hpp"
#include "XenCtrl.hpp"
#include "XenDeviceModel.hpp"
#include "XenEventChannel.hpp"
#include "XenForeignMemory.hpp"
#include "XenStore.hpp"

namespace xd::xen {

  using DomainAny = std::variant<DomainPV, DomainHVM>;

  class Xen : public std::enable_shared_from_this<Xen> {
  public:
    using SharedPtr = std::shared_ptr<Xen>;

    static SharedPtr create() {
      return std::make_shared<Xen>();
    }

    DomainAny init_domain(DomID domid);
    std::vector<DomainAny> get_domains();

    XenCall xencall;
    XenCtrl xenctrl;
    XenDeviceModel xendevicemodel;
    XenEventChannel xenevtchan;
    XenForeignMemory xenforeignmemory;
    XenStore xenstore;

  private:
    Xen() = default;
  };

}

#endif //XENDBG_XEN_HPP
