//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <memory>

#include <xenctrl.h>

#include "Common.hpp"

namespace xd::xen {

  class Domain;
  class Registers;

  class Xenctrl {
  private:
    struct XenVersion {
      int major, minor;
    };

  public:
    Xenctrl();

    XenVersion xen_version();

    DomInfo get_domain_info(Domain& domain);
    void get_cpu_context(Domain& domain, VCPU_ID vcpu_id);
    WordSize get_domain_word_size(Domain &domain);

    void set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void pause_domain(Domain& domain);
    void unpause_domain(Domain& domain);

  private:
    struct hvm_hw_cpu get_cpu_context_hvm(Domain& domain, VCPU_ID vcpu_id);
    vcpu_guest_context_any_t get_cpu_context_pv(Domain& domain, VCPU_ID vcpu_id);

  private:
    std::unique_ptr<xc_interface, decltype(&xc_interface_close)> _xenctrl;
  };

}

#endif //XENDBG_XENCTRL_HPP
