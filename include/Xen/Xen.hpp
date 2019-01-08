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
  private:
    struct ConstructorAccess {};

  public:
    Xen() = default;
    explicit Xen(ConstructorAccess ca) : Xen() {};

    static std::shared_ptr<Xen> create() {
      return std::make_shared<Xen>(ConstructorAccess{});
    }

    DomainAny init_domain(DomID domid);
    std::vector<DomainAny> get_domains();

    XenCtrl xenctrl;
    XenDeviceModel xendevicemodel;
    XenEventChannel xenevtchn;
    XenForeignMemory xenforeignmemory;
    XenStore xenstore;

    static xen::DomID get_domid_any(const xen::DomainAny &domain_any);
    static std::string get_name_any(const xen::DomainAny &domain_any);

    std::optional<xen::DomainAny> get_domain_from_name(const std::string &name);
    std::optional<xen::DomainAny> get_domain_from_domid(DomID domid);
  };

}

#endif //XENDBG_XEN_HPP
