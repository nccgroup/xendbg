See https://events.ccc.de/2018/09/11/35c3-call-for-participation-and-submission-guidelines/

# CCC CFP submission

* Title: `Xen VMI Debugging`
* Subtitle `An API Archeology Expedition`
* Event type: `lecture`
* Track: `Resilience`
* Time: `1 hr`
* Language: `English`
* Logo: `N/A`

Event classifiers: `Resilience` `(and Security?)`

# Summary

The Xen hypervisor is a gold standard for virtualization, employed across a
wide variety of major products and platforms. Despite the large number of
critical applications currently running on Xen, there are very few tools
available for performing virtual machine introspection (VMI) on Xen guests, and
as such, it is especially difficult to ensure the security and correctness of
applications targeting the platform. While Xen provides VMI debugging APIs,
they are extremely poorly documented and rarely used in practice. In this talk,
I will detail Xen's VMI APIs in full, as well as introducing `xendbg`, a
feature-complete reference implementation of a Xen VMI debugger.

# Long description 

The Xen hypervisor is a gold standard for virtualization, employed across a
wide variety of major products and platforms, from AWS on the cloud to
QubesOS on the desktop. Researchers have long been interested in the security
standing of Xen itself, but this is not by any means the only facet of
hypervisor security worthy of attention. With so many critical applications now
running on top of Xen, it is imperative that developers _also_ be able to test
the security and correctness of their applications when run as Xen guests.

The traditional method of debugging Xen guests is to run a debugger inside the
guest itself, but doing so has several limitations. Firstly, this only allows
inspecting the guest as it sees itself, not as the hypervisor can see it; any
truly comprehensive review of a hypervisor guest requires examining it
from both sides. Secondly, more exotic types of guest (e.g. unikernels,
which run only a single process in kernel space) possess no debugging
facilities of their own, and are practically undebuggable without external
introspection.

While Xen does provide introspection and debugging functionality, the APIs are
lacking and difficult to use. Hardware virtualized (HVM) guests support a
fairly complete set of VMI features, but paravirtualized (PV) guests are
essentially limited to PEEK/POKE debugging. Furthermore, the APIs in question
are extremely poorly documented; the overwhelming majority are not even
mentioned in Xen's documentation, only a meager amount of example code is
present in the codebase, and the implementations of the API functions
themselves are rarely even commented. Additionally, Xen has its own GDB stub
server, `gdbsx`, but its functionality is extremely limited, to the point of
being useless in practice.

In this talk, I will introduce and explain Xen's VMI APIs in full, with the
goal of providing enough information to allow others to construct full-featured
Xen debuggers and analysis tools. I will also introduce my own project,
`xendbg`, a feature-complete reference implementation of a Xen VMI debugger.
`xendbg` was originally written to further previous research on unikernels, and
has been useful in identifying exploitable unikernel security
misconfigurations.

# Submission notes

By introducing Xen's VMI APIs in detail, as well as providing a
feature-complete reference implementation in `xendbg`, I hope to enable the
development of additional tools for Xen that will help to improve the security
and correctness of applications targeting the platform.

# Links

# Uploaded file
