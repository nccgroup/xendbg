//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/ioctl.h>

#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"

#include "Common.hpp"
#include "Registers.hpp"

namespace xd::xen {

  class XenCtrl {
  private:
    struct XenVersion {
      int major, minor;
    };

  public:
    XenCtrl();

    XenVersion get_xen_version();

    DomInfo get_domain_info(Domain &domain);
    Registers get_domain_cpu_context(Domain &domain, VCPU_ID vcpu_id = 0);
    WordSize get_domain_word_size(Domain &domain);
    MemInfo map_domain_meminfo(Domain &domain);

    void set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id);
    void pause_domain(Domain &domain);
    void unpause_domain(Domain &domain);

  private:
    struct hvm_hw_cpu get_domain_cpu_context_hvm(Domain &domain, VCPU_ID vcpu_id);
    vcpu_guest_context_any_t get_domain_cpu_context_pv(Domain &domain, VCPU_ID vcpu_id);

  private:
    std::shared_ptr<xc_interface> _xenctrl;
  };

}

#endif //XENDBG_XENCTRL_HPP
