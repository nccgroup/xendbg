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

#ifndef XENDBG_XENSTORE_HPP
#define XENDBG_XENSTORE_HPP

#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "BridgeHeaders/xenstore.h"
#include "Common.hpp"

namespace xd::xen {

  class XenStore {
  public:
    class Watch;
    using Path = std::string;
    using Token = std::string;

    XenStore();

    struct xs_handle *get() { return _xenstore.get(); };
    int get_fileno() const;

    Watch &add_watch();

    std::string read(const std::string& file) const;
    std::vector<std::string> read_directory(const std::string& dir) const;

  public:
    class Watch {
    public:
      Watch(XenStore &xenstore, std::string token);
      ~Watch();

      Watch(Watch&& other) = default;
      Watch(const Watch& other) = delete;
      Watch& operator=(Watch&& other) = default;
      Watch& operator=(const Watch& other) = delete;

      void add_path(Path path);
      std::optional<Path> check();

    private:
      friend class XenStore;

      XenStore &_xenstore;
      Token _token;
      std::vector<std::string> _paths;

      std::queue<Path> _events;
    };

  private:
    std::unique_ptr<struct xs_handle, decltype(&xs_close)> _xenstore;
    std::unordered_map<Token, Watch> _watches;
    size_t _next_watch_id;

    void check_watches();

  };
}

#endif //XENDBG_XENSTORE_HPP
