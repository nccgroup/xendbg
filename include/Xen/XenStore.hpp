//
// Created by Spencer Michaels on 8/13/18.
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
