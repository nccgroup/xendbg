//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_PAGETABLEENTRY_HPP
#define XENDBG_PAGETABLEENTRY_HPP

#include "Common.hpp"

namespace xd::xen {

  class Domain;

  class PageTableEntry {
  public:
    using RawPTE = uint64_t;

    enum class Level {
      L1, L2, L3, L4
    };

    static PageTableEntry read_level(const Domain &domain, Address virtual_address,
        Address mfn, Level level);

	public:
    PageTableEntry(uint64_t pte)
      : _pte(pte) {};

    Address get_mfn() const;

    bool is_present() const;
    bool is_rw() const;
    bool is_user() const;
    bool is_pwt() const;
    bool is_pcd() const;
    bool is_accessed() const;
    bool is_dirty() const;
    bool is_pat() const;
    bool is_pse() const;
    bool is_global() const;
    bool is_nx() const;
    bool is_grant_table() const;
    bool is_guest_kernel() const;

  private:
    uint64_t _pte;

    uint64_t get_flags() const;

    static unsigned get_pte_offset(Address address, Level level);
  };

}

#endif //XENDBG_PAGETABLEENTRY_HPP
