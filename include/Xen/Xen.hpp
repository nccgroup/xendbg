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
