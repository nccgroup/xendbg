#include <stdlib.h>

#include "UVLoop.hpp"
#include "../uvcast.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;

UVLoop::UVLoop() {
  uv_loop_init(&_loop);
}

UVLoop::~UVLoop() {
  uv_loop_close(&_loop);
}

void UVLoop::start() {
  uv_run(&_loop, UV_RUN_DEFAULT);
}

void UVLoop::stop() {
  uv_stop(&_loop);
}
