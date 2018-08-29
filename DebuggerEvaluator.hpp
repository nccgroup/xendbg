//
// Created by Spencer Michaels on 8/29/18.
//

#ifndef XENDBG_DEBUGGEREVALUATOR_HPP
#define XENDBG_DEBUGGEREVALUATOR_HPP

#include "Parser/Expression/ExpressionEvaluator.hpp"
#include "Debugger.hpp"

namespace xd {

  class DebuggerEvaluator : parser::expr::ExpressionEvaluator {
  public:
    explicit DebuggerEvaluator(Debugger& debugger);

    void operator()(const parser::expr::BinaryExpression &ex) override;
    void operator()(const parser::expr::Constant &ex) override;
    void operator()(const parser::expr::Label &ex) override;
    void operator()(const parser::expr::UnaryExpression &ex) override;
    void operator()(const parser::expr::Variable &ex) override;

  private:
    Debugger &_debugger;
  };

}


#endif //XENDBG_DEBUGGEREVALUATOR_HPP
