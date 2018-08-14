//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>

#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xenstore.h>
#include <version.h>

#include "XenException.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenException;
using xd::xen::XenHandle;

