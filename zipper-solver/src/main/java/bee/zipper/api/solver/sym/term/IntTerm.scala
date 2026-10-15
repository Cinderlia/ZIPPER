package bee.zipper.api.solver.sym.term

import bee.zipper.util.AnyExtension.*

trait IntTerm extends Term

trait IntBinOp extends IntTerm, BinOp

case class IntLiteral(value: Long) extends ConstantValue, IntTerm {
  override def toString: String = value.toString
}

case class IntVar(name: String) extends IntTerm, VarTerm {
  override def toString: String = s"i:$name"
}

case class StringLength(str: StringTerm) extends IntTerm, HasOperands {
  override def toString: String = s"length($str)"

  override def operands: List[Term] = List(str)
}

object StringLength {
  def create(str: StringTerm): IntTerm = {
    str match {
      case StringLiteral(value) => IntLiteral(value.length)
      case _                    => StringLength(str)
    }
  }
}

case class ToInt(str: StringTerm) extends IntTerm, HasOperands {
  override def toString: String = s"toInt($str)"

  override def operands: List[Term] = List(str)
}

object ToInt {
  def create(str: StringTerm): IntTerm = {
    str match {
      case StringLiteral(value) => value.toIntOption.map(IntLiteral(_)).getOrElse(ToInt(str))
      case _                    => StringLength(str)
    }
  }
}

case class IndexOf(str: StringTerm, sub: StringTerm, offset: IntTerm = IntLiteral(0)) extends IntTerm, HasOperands {
  override def toString: String = s"indexOf($str, $sub, $offset)"

  override def operands: List[Term] = List(str, sub, offset)
}

object IndexOf {
  def create(str: StringTerm, sub: StringTerm): IntTerm = {
    (str, sub) match {
      case (StringLiteral(x), StringLiteral(y)) => IntLiteral(x.indexOf(y))
      case _                                    => IndexOf(str, sub)
    }
  }
}

case class Add(lhs: IntTerm, rhs: IntTerm) extends IntBinOp {
  override def toString: String = s"add($lhs, $rhs)"
}

object Add {
  def create(lhs: IntTerm, rhs: IntTerm): IntTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => IntLiteral(x + y)
      case _                              => Add(lhs, rhs)
    }
  }
}

case class Mul(lhs: IntTerm, rhs: IntTerm) extends IntBinOp {
  override def toString: String = s"mul($lhs, $rhs)"

  override def operands: List[Term] = List(lhs, rhs)
}

object Mul {
  def create(lhs: IntTerm, rhs: IntTerm): IntTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => IntLiteral(x * y)
      case _                              => Mul(lhs, rhs)
    }
  }
}

case class Sub(lhs: IntTerm, rhs: IntTerm) extends IntBinOp {
  override def toString: String = s"sub($lhs, $rhs)"

  override def operands: List[Term] = List(lhs, rhs)
}

object Sub {
  def create(lhs: IntTerm, rhs: IntTerm): IntTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => IntLiteral(x - y)
      case _                              => Sub(lhs, rhs)
    }
  }
}
