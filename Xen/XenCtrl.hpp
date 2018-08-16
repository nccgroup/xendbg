//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <memory>

#include "BridgeHeaders/XenCtrl.h"

#include "Common.hpp"
#include "Registers.hpp"

namespace xd::xen {

  class Domain;

  class XenCtrl {
  private:
    struct XenVersion {
      int major, minor;
    };

  public:
    XenCtrl();

    XenVersion xen_version();

    DomInfo get_domain_info(Domain& domain);
    Registers get_cpu_context(Domain& domain, VCPU_ID vcpu_id);
    WordSize get_domain_word_size(Domain &domain);

    void set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void pause_domain(Domain& domain);
    void unpause_domain(Domain& domain);

  private:
    struct hvm_hw_cpu get_cpu_context_hvm(Domain& domain, VCPU_ID vcpu_id);
    vcpu_guest_context_any_t get_cpu_context_pv(Domain& domain, VCPU_ID vcpu_id);
    xen_pfn_t pfn_to_mfn_pv(xen_pfn_t pfn, xen_pfn_t *pfn_to_gfn_table, WordSize word_size);
    std::unique_ptr<struct xc_domain_meminfo> map_domain_meminfo(Domain& domain);

  private:
    std::unique_ptr<xc_interface, decltype(&xc_interface_close)> _xenctrl;
  };

}

#endif //XENDBG_XENCTRL_HPP
