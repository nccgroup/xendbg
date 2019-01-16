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

#ifndef XENDBG_PAGETABLEENTRY_HPP
#define XENDBG_PAGETABLEENTRY_HPP

#include <optional>

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

    operator bool() const { return is_present(); };

    Address get_mfn() const;
    uint64_t get_raw() const { return _pte; }

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
