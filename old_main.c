#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xenctrl.h>
#include <xenstore.h>
#include <xenforeignmemory.h>

typedef struct registers_x86 {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t dr7;
    uint64_t rip;
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3;
    uint64_t cr4;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t msr_efer;
    uint64_t msr_star;
    uint64_t msr_lstar;
    uint64_t fs_base;
    uint64_t gs_base;
    uint32_t cs_arbytes;
    uint32_t _pad;
} registers_x86_t;

typedef registers_x86_t registers_t;

typedef struct xen_handle {
  xc_interface* xenctrl;
  struct xs_handle* xenstore;
  xenforeignmemory_handle fmem;

  int version_major;
  int version_minor;
} xen_handle_t;

typedef struct xen_domain {
  char *name;
  xc_dominfo_t info;
} xen_domain_t;

void xdb_die(const char* fmt, ...);
void xdb_log(const char* fmt, ...);

void xdb_xen_init(xen_handle_t *xen);
void xdb_domain_get_info(xen_handle_t *xen, xen_domain_t *domain, uint32_t domid);
void xdb_domain_get_name(xen_handle_t *xen, xen_domain_t *domain, char **name);
uint32_t xdb_domain_get_id_from_name(xen_handle_t *xen, char *name);
void xdb_domain_set_debugging(xen_handle_t *xen, xen_domain_t *domain, unsigned int enable);
void xdb_domain_set_single_step(xen_handle_t *xen, xen_domain_t *domain, unsigned int vcpu,
    unsigned int enable);
void xdb_domain_pause(xen_handle_t *xen, xen_domain_t *domain);
void xdb_domain_unpause(xen_handle_t *xen, xen_domain_t *domain);

void xdb_domain_hvm_register_read(xen_handle_t *xen, xen_domain_t *domain, unsigned long vcpu, registers_t *regs);

void xdb_domain_pv_register_read(xen_handle_t *xen, xen_domain_t *domain, unsigned long vcpu, registers_t *regs);
//void xdb_domain_pv_register_write(xen_handle_t *xen, xen_domain_t *domain, unsigned long vcpu, registers_t *regs);

void xdb_domain_memory_read(xen_handle_t *xen, xen_domain_t *domain, addr_t addr);


int main(int argc, char** argv) {
  assert(argc == 2);
  char *domid_or_name = argv[1];

  xen_handle_t xen;
  xdb_xen_init(&xen);
  xdb_log("Connected to Xen %d.%d interface.\n",
      xen.version_major, xen.version_minor);

  uint32_t domid = strtoull(domid_or_name, NULL, 10);
  if (!domid) domid = xdb_domain_get_id_from_name(&xen, domid_or_name);
  if (!domid) xdb_die("Unknown domain name or ID: %s.\n", domid_or_name);

  xen_domain_t domain;
  xdb_domain_get_info(&xen, &domain, domid);
  xdb_domain_get_name(&xen, &domain, &domain.name);
  xdb_log("Connected to domain %d (%s).\n", domain.info.domid, domain.name);

  registers_t regs;
  xdb_domain_set_debugging(&xen, &domain, 1);
  xdb_log("Enabled debugging.\n");
  xdb_domain_pause(&xen, &domain);

  xdb_domain_get_info(&xen, &domain, domid);
  assert(!domain.info.dying);
  assert(domain.info.debugged);
  assert(!domain.info.hvm); // TODO: Only PV support for now

  for (int i = 0; i <= domain.info.max_vcpu_id; ++i) {
    xdb_domain_pv_register_read(&xen, &domain, &regs, i);
    xdb_log("rip: 0x%016x\n", regs.rip);
  }
}

void xdb_die(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  exit(1);
}

void xdb_log(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

void xdb_xen_init(xen_handle_t *xen) {
  if (!(xen->xenctrl = xc_interface_open(NULL, NULL, 0))) {
    xdb_die("Failed to open Xen interface!\n");
  }

  {
    int version = xc_version(xen->xenctrl, XENVER_version, NULL);
    xen->version_major = version >> 16;
    xen->version_minor = version & ((1 << 16) - 1);
  }

  if (!(xen->xenstore = xs_open(0))) {
    xdb_die("Failed to open Xenstore!\n");
  }

  if (!(xen->fmem = xenforeignmemory_open(NULL, 0))) {
    xdb_die("Failed to open Xenstore!\n");
  }
}

void xdb_xen_deinit(xen_handle_t *xen) {
  if (xen->xenctrl) xc_interface_close(xen->xenctrl);
  if (xen->xenstore) xs_close(xen->xenstore);
  if (xen->fmem) xenforeignmemory_close(xen->fmem);
}

void xdb_domain_get_info(xen_handle_t *xen, xen_domain_t *domain, uint32_t domid) {
  xc_domain_getinfo(xen->xenctrl, domid, 1, &domain->info);

  if (domain->info.domid != domid)
    xdb_die("Failed to init domain %d!\n", domid);
}

void xdb_domain_get_name(xen_handle_t *xen, xen_domain_t *domain, char **name) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenstore) xdb_die("Xenstore handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  char path[128];
  xs_transaction_t xth = XBT_NULL;

  snprintf((char * restrict)&path, 128, "/local/domain/%u/name", domain->info.domid);
  *name = xs_read(xen->xenstore, xth, (char*)&path, NULL);

  if (*name == NULL) {
    xdb_die("Failed to get name of domain %u.\n", domain->info.domid);
  }
}

uint32_t xdb_domain_get_id_from_name(xen_handle_t *xen, char *name) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenstore) xdb_die("Xenstore handle is null!");
  if (!name)          xdb_die("Name is null!");

  unsigned int domains_size;
  xs_transaction_t xth = XBT_NULL;
  char **domains = xs_directory(xen->xenstore, xth, "/local/domain", &domains_size);

  for (int i = 0; i < domains_size; ++i) {
    char* id_str = domains[i];

    char path[128];
    snprintf((char * restrict)&path, 128, "/local/domain/%s/name", id_str);
    char *name_candidate = (char*)xs_read(xen->xenstore, xth, (char*)&path, NULL);

    if (name_candidate != NULL && !strncmp(name, name_candidate, 128)) {
        return strtoull(id_str, NULL, 10);
    }
  }

  return 0;
}

void xdb_domain_set_debugging(xen_handle_t *xen, xen_domain_t *domain, unsigned int enable) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  if (xc_domain_setdebugging(xen->xenctrl, domain->info.domid, enable)) {
    xdb_die("Failed to enable debugging on domain %d!\n", domain->info.domid);
  }
}

void xdb_domain_pause(xen_handle_t *xen, xen_domain_t *domain) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  if (xc_domain_pause(xen->xenctrl, domain->info.domid)) {
    xdb_die("Failed pause domain %d!", domain->info.domid);
  }
}

void xdb_domain_unpause(xen_handle_t *xen, xen_domain_t *domain) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  if (xc_domain_unpause(xen->xenctrl, domain->info.domid)) {
    xdb_die("Failed to unpause domain %d!", domain->info.domid);
  }
}

void xdb_domain_set_single_step(xen_handle_t *xen, xen_domain_t *domain, unsigned int vcpu,
    unsigned int enable) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  uint32_t op = enable ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (xc_domain_debug_control(xen->xenctrl, domain->info.domid, op, vcpu)) {
    xdb_die("Failed to %s single-step mode on domain %lu, vCPU %u.\n",
        enable ? "enable" : "disable", domain->info.domid, vcpu);
  }
}

void xdb_domain_hvm_register_read(xen_handle_t *xen, xen_domain_t *domain, unsigned long vcpu,
        registers_t *regs) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  struct hvm_hw_cpu context;
  if (xc_domain_hvm_getcontext_partial(xen->xenctrl, domain->info.domid, HVM_SAVE_CODE(CPU),
        vcpu, &context, sizeof(context))) {
    xdb_die("Failed to get context for domain %d, vCPU %d.\n", domain->info.domid, vcpu);
  }

  regs->rax = context.rax;
  regs->rbx = context.rbx;
  regs->rcx = context.rcx;
  regs->rdx = context.rdx;
  regs->rbp = context.rbp;
  regs->rsi = context.rsi;
  regs->rdi = context.rdi;
  regs->rsp = context.rsp;
  regs->r8 = context.r8;
  regs->r9 = context.r9;
  regs->r10 = context.r10;
  regs->r11 = context.r11;
  regs->r12 = context.r12;
  regs->r13 = context.r13;
  regs->r14 = context.r14;
  regs->r15 = context.r15;
  regs->rip = context.rip;
  regs->rflags = context.rflags;
  regs->cr0 = context.cr0;
  regs->cr2 = context.cr2;
  regs->cr3 = context.cr3;
  regs->cr4 = context.cr4;
  regs->dr7 = context.dr7;
  regs->fs_base = context.fs_base;
  regs->gs_base = context.gs_base;
  regs->cs_arbytes = context.cs_arbytes;
  regs->sysenter_cs = context.sysenter_cs;
  regs->sysenter_esp = context.sysenter_esp;
  regs->sysenter_eip = context.sysenter_eip;
  regs->msr_efer = context.msr_efer;
  regs->msr_star = context.msr_star;
  regs->msr_lstar = context.msr_lstar;
}

void xdb_domain_pv_register_read(xen_handle_t *xen, xen_domain_t *domain, unsigned long vcpu,
        registers_t *regs) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  vcpu_guest_context_any_t context_any;
  if (xc_vcpu_getcontext(xen->xenctrl, domain->info.domid, vcpu, &context_any)) {
    xdb_die("Failed to get context for domain %d, vCPU %d.\n", domain->info.domid, vcpu);
  };

  // TODO: Only supports 64-bit for now
  vcpu_guest_context_x86_64_t *context = &context_any.x64;

  regs->rax = context->user_regs.rax;
  regs->rbx = context->user_regs.rbx;
  regs->rcx = context->user_regs.rcx;
  regs->rdx = context->user_regs.rdx;
  regs->rbp = context->user_regs.rbp;
  regs->rsi = context->user_regs.rsi;
  regs->rdi = context->user_regs.rdi;
  regs->rsp = context->user_regs.rsp;
  regs->r8 = context->user_regs.r8;
  regs->r9 = context->user_regs.r9;
  regs->r10 = context->user_regs.r10;
  regs->r11 = context->user_regs.r11;
  regs->r12 = context->user_regs.r12;
  regs->r13 = context->user_regs.r13;
  regs->r14 = context->user_regs.r14;
  regs->r15 = context->user_regs.r15;
  regs->rip = context->user_regs.rip;
  regs->rflags = context->user_regs.rflags;
  regs->cr0 = context->ctrlreg[0];
  regs->cr2 = context->ctrlreg[2];
  regs->cr3 = context->ctrlreg[3];
  regs->cr4 = context->ctrlreg[4];
  regs->fs_base = context->fs_base;
  regs->gs_base = context->gs_base_kernel;
}

typedef uint64_t addr_t;

void xdb_domain_memory_read(xen_handle_t *xen, xen_domain_t *domain, addr_t addr,
        uint32_t size) {
  addr_t pfn = addr >> XC_PAGE_SHIFT;
  return xdb_domain_get_memory(xen, domain, pfn, size, PROT_READ);
}

void xdb_domain_get_memory(xen_handle_t *xen, xen_domain_t *domain, unsigned long base_pfn,
        uint32_t size, int prot) {
  if (!xen)           xdb_die("Xen handle is null!");
  if (!xen->xenctrl)  xdb_die("Xenctrl handle is null!");
  if (!domain)        xdb_die("Domain handle is null!");

  xen_pfn_t *pages;
  int num_pages = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;
  assert(num_pages >= 0);

  if (!(pages = calloc(num_pages, sizeof(xen_pfn_t))) {
    xdb_die("calloc failed!\n");
  }

  int *errors;
  for (int i = 0; i < num_pages; ++i) {
    pages[i] = base_pfn + i;
  }

  void *mem = xenforeignmemory_map(xen->fmem, domain->info.domid, prot, num_pages,
    mfns, errors);
  
  if (mem == MAP_FAILED || mem == NULL) {
    xdb_die("Failed to map memory for domain %d!\n", domain->info.domid);
    return NULL;
  }

  for (int i = 0; i < num_pages; ++i) {
    if (errors[i]) {
      xdb_die("Mapping failed for PFN %d (error %d)\n", pfns[i], errors[i]);
    };
  }

  return mem;
}
