package bee.zipper.api.solver.sym

import bee.zipper.api.solver.sym.extend.UntypedVariable
import bee.zipper.api.solver.sym.term.*

/** stateless symbolic value casting utility
  */
object SymCast {
  def toInt(term: SymbolicValue): IntTerm = {
    term match {
      case int: IntTerm    => int
      case str: StringTerm => ToInt.create(str)
      case bool: BoolTerm  => IntITE.create(bool, IntLiteral(1), IntLiteral(0))
      case uv: UntypedVariable =>
        uv.name match {
          case StringLiteral(name) => IntVar(name)
          case _                   => IntLiteral(0)
        }
      case _ => IntLiteral(0)
    }
  }

  def toBool(term: SymbolicValue): BoolTerm = {
    term match {
      case int: IntTerm =>
        int match {
          case literal: IntLiteral =>
            BoolLiteral(literal.value != 0)
          case _ =>
            val condition = IntEqual.create(int, IntLiteral(0))
            BoolITE.create(condition, BoolLiteral(false), BoolLiteral(true))
        }
      case str: StringTerm => BoolLiteral(true)
      case bool: BoolTerm  => bool
      case uv: UntypedVariable =>
        uv.name match {
          case StringLiteral(name) => BoolVar(name)
          case _                   => BoolLiteral(true)
        }
      case _ => BoolLiteral(true)
    }
  }

  def toStr(term: SymbolicValue): StringTerm = {
    term match {
      case int: IntTerm    => FromInt.create(int)
      case str: StringTerm => str
      case bool: BoolTerm  => StringITE.create(bool, StringLiteral("true"), StringLiteral("false"))
      case sv: UntypedVariable =>
        sv.name match {
          case StringLiteral(name) => StringVar(name)
          case _                   => StringLiteral("")
        }
      case _ => StringLiteral("")
    }
  }
}
