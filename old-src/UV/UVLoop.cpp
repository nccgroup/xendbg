#include <stdlib.h>

#include <UV/UVLoop.hpp>
#include <UV/UVCast.hpp>

using uvcast::uv_upcast;
using xd::uv::UVLoop;

UVLoop::UVLoop()
  : _loop(new uv_loop_t, &uv_loop_close)
{
  uv_loop_init(_loop.get());
}

UVLoop::UVLoop(UVLoop&& other)
  : _loop(std::move(other._loop))
{}

UVLoop& UVLoop::operator=(UVLoop&& other) {
  _loop = std::move(other._loop);
  return *this;
}

void UVLoop::start() {
  uv_run(_loop.get(), UV_RUN_DEFAULT);
}

void UVLoop::stop() {
  uv_stop(_loop.get());
}
