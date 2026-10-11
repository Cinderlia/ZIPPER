package bee.zipper.api.solver.sym.term

trait SymbolicValue

trait Term extends SymbolicValue

trait ConstantValue extends Term

trait VarTerm extends Term {
  def name: String
}

trait HasOperands {
  def operands: List[Term]
}

trait BinOp extends Term, HasOperands {
  def lhs: Term

  def rhs: Term

  override def operands: List[Term] = List(lhs, rhs)
}
