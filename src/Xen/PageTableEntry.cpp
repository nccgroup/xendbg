#include <sys/mman.h>
#include <variant>

#include <Util/overloaded.hpp>
#include <Xen/Domain.hpp>
#include <Xen/PageTableEntry.hpp>

using xd::xen::Address;
using xd::xen::PageTableEntry;

static const unsigned long
  PAGETABLE_ORDER     = 9,
  PAGETABLE_ENTRIES   = 1 << PAGETABLE_ORDER,
  PAGETABLE_SHIFTS[4] = { 12, 21, 30, 39 },
  PADDR_BITS =        64 - XC_PAGE_SHIFT,
  PADDR_MASK =        (1ULL << PADDR_BITS) - 1;

enum PAGE_FLAGS {
  _PAGE_PRESENT       = 1U,
  _PAGE_RW            = 1U << 1,
  _PAGE_USER          = 1U << 2,
  _PAGE_PWT           = 1U << 3,
  _PAGE_PCD           = 1U << 4,
  _PAGE_ACCESSED      = 1U << 5,
  _PAGE_DIRTY         = 1U << 6,
  _PAGE_PAT_PSE       = 1U << 7,
  _PAGE_GLOBAL        = 1U << 8,
  _PAGE_GNTTAB        = 1U << 22,
  _PAGE_NX            = 1U << 23,
  _PAGE_GUEST_KERNEL  = 1U << 12
};

static inline size_t get_pagetable_shift(PageTableEntry::Level level) {
  const auto level_index = 
    static_cast<typename std::underlying_type<PageTableEntry::Level>::type>(level);
  return PAGETABLE_SHIFTS[level_index];
}

PageTableEntry PageTableEntry::read_level(const Domain &domain,
    Address virtual_address, Address mfn, Level level)
{
  const auto table = domain.map_memory_by_mfn<RawPTE>(
      mfn, 0, XC_PAGE_SIZE, PROT_READ);
  const auto offset = get_pte_offset(virtual_address, level);
  const auto pte = (table.get())[offset];
  return PageTableEntry(pte);
}

unsigned PageTableEntry::get_pte_offset(Address address, Level level) {
  return (((address) >> get_pagetable_shift(level)) & (PAGETABLE_ENTRIES - 1));
}

uint64_t PageTableEntry::get_flags() const {
  return ((int)((_pte) >> 40) & ~0xFFF) | ((int)(_pte) & 0xFFF);
}

Address PageTableEntry::get_mfn() const {
  return (_pte & (PADDR_MASK & XC_PAGE_MASK)) >> XC_PAGE_SHIFT;
}

bool PageTableEntry::is_present() const   { return (get_flags() & _PAGE_PRESENT); };
bool PageTableEntry::is_rw() const        { return (get_flags() & _PAGE_RW); };
bool PageTableEntry::is_user() const      { return (get_flags() & _PAGE_USER); };
bool PageTableEntry::is_pwt() const       { return (get_flags() & _PAGE_PWT); };
bool PageTableEntry::is_pcd() const       { return (get_flags() & _PAGE_PCD); };
bool PageTableEntry::is_accessed() const  { return (get_flags() & _PAGE_ACCESSED); };
bool PageTableEntry::is_dirty() const     { return (get_flags() & _PAGE_DIRTY); };
bool PageTableEntry::is_pat() const       { return (get_flags() & _PAGE_PAT_PSE); };
bool PageTableEntry::is_pse() const       { return (get_flags() & _PAGE_PAT_PSE); };
bool PageTableEntry::is_global() const    { return (get_flags() & _PAGE_GLOBAL); };
bool PageTableEntry::is_nx() const        { return (get_flags() & _PAGE_NX); };
bool PageTableEntry::is_grant_table() const   { return (get_flags() & _PAGE_GNTTAB); };
bool PageTableEntry::is_guest_kernel() const  { return (get_flags() & _PAGE_GUEST_KERNEL); };
