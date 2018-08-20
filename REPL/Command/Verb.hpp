//
// Created by Spencer Michaels on 8/19/18.
//

#ifndef XENDBG_VERB_HPP
#define XENDBG_VERB_HPP

#include <optional>
#include <string>
#include <variant>

#include "Action.hpp"

namespace xd::repl::cmd {

  class VerbBase {
  public:
    virtual std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const = 0;
  };

  template <template <typename> class A, typename... Ts>
  struct pack {
    using Variant = std::variant<A<Ts>...>;

    pack(A<Ts>... is) : items{is...} {};
    std::vector<Variant> items;
  };

  template <typename FlagsPack_t, typename ArgsPack_t>
  class Verb : public VerbBase {
  private:
  using ActionMaker = std::function<Action(
      const typename FlagsPack_t::Variant&, const typename ArgsPack_t::Variant&)>;

  public:
    Verb(std::string name, std::string description,
        FlagsPack_t flags, ArgsPack_t args, ActionMaker)
      : _name(std::move(name)), _description(std::move(description)) {};

    std::string get_name() const { return _name; };

    std::optional<Action> match(std::string::const_iterator begin,
        std::string::const_iterator end) const override;

  private:
    const std::string _name;
    const std::string _description;
  };

}

#endif //XENDBG_VERB_HPP
