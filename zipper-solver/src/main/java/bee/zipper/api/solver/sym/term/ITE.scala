package bee.zipper.api.solver.sym.term

/** if-then-else statement
  */
trait ITE extends Term, HasOperands {
  def condition: BoolTerm

  def thenBody: Term

  def elseBody: Term

  override def operands: List[Term] = List(condition, thenBody, elseBody)

  override def toString: String = s"if ($condition) then ($thenBody) else ($elseBody)"
}

case class IntITE(condition: BoolTerm, thenBody: IntTerm, elseBody: IntTerm) extends IntTerm, ITE

object IntITE {
  def create(condition: BoolTerm, thenBody: IntTerm, elseBody: IntTerm): IntTerm = {
    condition match {
      case BoolLiteral(c) => if (c) thenBody else elseBody
      case _              => IntITE(condition, thenBody, elseBody)
    }
  }
}

case class BoolITE(condition: BoolTerm, thenBody: BoolTerm, elseBody: BoolTerm) extends BoolTerm, ITE

object BoolITE {
  def create(condition: BoolTerm, thenBody: BoolTerm, elseBody: BoolTerm): BoolTerm = {
    condition match {
      case BoolLiteral(c) => if (c) thenBody else elseBody
      case _              => BoolITE(condition, thenBody, elseBody)
    }
  }
}

case class StringITE(condition: BoolTerm, thenBody: StringTerm, elseBody: StringTerm) extends StringTerm, ITE

object StringITE {
  def create(condition: BoolTerm, thenBody: StringTerm, elseBody: StringTerm): StringTerm = {
    condition match {
      case BoolLiteral(c) => if (c) thenBody else elseBody
      case _              => StringITE(condition, thenBody, elseBody)
    }
  }
}
