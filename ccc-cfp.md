See https://events.ccc.de/2018/09/11/35c3-call-for-participation-and-submission-guidelines/

# CCC CFP submission

* Title: `Xen VM Introspection`
* Subtitle: `Using Xen's VMI APIs to ensure guest security & correctness`
* Event type: `lecture`
* Track: `Resilience`
* Time: `1 hr`
* Language: `English`
* Logo: `N/A`

Event classifiers: `Resilience` `(and Security?)`

# Summary

# Long description 

The Xen hypervisor is a gold standard for virtualization, employed across a
wide variety of major products and platforms, from AWS\* on the cloud to
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

While the Xen API does provide introspection and debugging functionality, it is
both incomplete and difficult to use. Hardware virtualized guests support
fairly complete set of VMI features, but paravirtualized guests are essentially
limited to PEEK/POKE debugging. Furthermore, the APIs in question are extremely
poorly documented: the overwhelming majority are not even mentioned in Xen's
documentation, only a meager amount of example code is present in the codebase,
and the implementations of the API functions themselves are rarely even commented.

Xen has its own GDB stub server, `gdbsx`, which in theory supports at most
PEEK/POKE debugging, and in practice is so broken as to be useless, as it does
not properly implement either the GDB or LLDB remote protocol, rendering it
largely incapable of communicating with either debugger. Furthermore, `gdbsx`
does not even use the actual Xen VMI APIs, instead relying on custom hypercalls
designed specifically for use by `gdbsx` --- presumably a result of the
documentation for those APIs being nearly nonexistent.

In this talk I will introduce and explain Xen's VMI APIs in full, with the goal
of providing enough information to allow others to construct full-featured Xen
debuggers and analysis tools. I will also introduce my own project, `xendbg`,
which I originally wrote as part of my earlier research on unikernels, and
which eventually resulted in the birth of this talk. `xendbg` supports all the
major features of a locally-run debugger, can inspect both HVM and PV Xen
guests, and can run either as an LLDB server or a standalone REPL. By
introducing Xen's VMI APIs in detail, as well as providing a feature-complete,
standalone example in `xendbg`, I hope to enable the development of additional
tools for Xen that will help to improve the security and correctness of
applications targeting the platform.

# Submission notes

# Links

# Uploaded file
