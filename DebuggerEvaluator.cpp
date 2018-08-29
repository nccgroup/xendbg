//
// Created by Spencer Michaels on 8/29/18.
//

#include "DebuggerEvaluator.hpp"

xd::DebuggerEvaluator::DebuggerEvaluator(xd::Debugger &debugger)
  : _debugger(debugger)
{
}

void xd::DebuggerEvaluator::operator()(const xd::parser::expr::BinaryExpression &ex) {
}

void xd::DebuggerEvaluator::operator()(const xd::parser::expr::Constant &ex) {
}

void xd::DebuggerEvaluator::operator()(const xd::parser::expr::Label &ex) {
}

void xd::DebuggerEvaluator::operator()(const xd::parser::expr::UnaryExpression &ex) {
}

void xd::DebuggerEvaluator::operator()(const xd::parser::expr::Variable &ex) {
}
