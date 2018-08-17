//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <memory>

#include "BridgeHeaders/domctl.h"
#include "BridgeHeaders/hypercall.h"
#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"

#include "Common.hpp"
#include "Domain.hpp"
#include "Registers.hpp"

namespace xd::xen {

  class XenCtrl {
  private:
    struct XenVersion {
      int major, minor;
    };

  public:
    XenCtrl();

    XenVersion xen_version();

    DomInfo get_domain_info(Domain& domain);
    Registers get_cpu_context(Domain& domain, VCPU_ID vcpu_id = 0);
    WordSize get_domain_word_size(Domain &domain);
    MemInfo map_domain_meminfo(Domain& domain);

    void set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void pause_domain(Domain& domain);
    void unpause_domain(Domain& domain);

      template <typename InitFn_t>
    void hypercall(Domain& domain, uint32_t command, InitFn_t init_domctl) {
      xen_domctl domctl;
      domctl.domain = domain.get_domid();
      domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
      domctl.cmd = command;

      memset(&domctl.u, 0, sizeof(domctl.u))
      init_domctl(domctl.u);
      do_domctl(_xenctrl.get(), &domctl);
    }

  private:
    struct hvm_hw_cpu get_cpu_context_hvm(Domain& domain, VCPU_ID vcpu_id);
    vcpu_guest_context_any_t get_cpu_context_pv(Domain& domain, VCPU_ID vcpu_id);

  private:
    std::shared_ptr<xc_interface> _xenctrl;
  };

}

#endif //XENDBG_XENCTRL_HPP
