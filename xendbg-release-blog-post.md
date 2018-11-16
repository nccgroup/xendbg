# Introducing Xendbg

The Xen hypervisor is a gold standard for virtualization, employed across a
wide variety of major products and platforms. Despite the large number of
critical applications currently running on Xen, there are very few tools
available for performing virtual machine introspection (VMI) on Xen guests,
partly because Xen's VMI debugging APIs are almost completely undocumented.
Given this lack of tooling, it is especially difficult to ensure the security
and correctness of applications targeting Xen.

`xendbg`, a feature-complete reference implementation of a Xen VMI debugger.

# Features
- Supports paravirtualized (PV) and hardware virtualized (HVM) guests
- Register and memory read/write
- Breakpoints & single-stepping
- Memory watchpoints (HVM only)
