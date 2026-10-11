package bee.zipper.api.solver.sym.term

import bee.zipper.api.solver.sym.extend.DummyObject
import bee.zipper.util.AnyExtension.*

trait BoolTerm extends Term

trait BoolBinOp extends BoolTerm, BinOp

case class BoolLiteral(value: Boolean) extends ConstantValue, BoolTerm {
  override def toString: String = value.toString
}

case class BoolVar(name: String) extends BoolTerm, VarTerm {
  override def toString: String = s"b:$name"
}

case class StringContains(subject: StringTerm, target: StringTerm) extends BoolTerm, HasOperands {
  override def toString: String = s"str_contains($subject, $target)"

  override def operands: List[Term] = List(subject, target)
}

object StringContains {
  def create(subject: StringTerm, target: StringTerm): BoolTerm = {
    (subject, target) match {
      case (StringLiteral(x), StringLiteral(y)) => BoolLiteral(x.contains(y))
      case _                                    => StringContains(subject, target)
    }
  }
}

case class ReMatch(subject: StringTerm, pattern: StringTerm) extends BoolTerm, HasOperands {
  override def toString: String = s"$subject ∈ L($pattern)"

  override def operands: List[Term] = List(subject, pattern)
}

object ReMatch {
  def create(subject: StringTerm, pattern: StringTerm): BoolTerm = {
    (subject, pattern) match {
      case (StringLiteral(s), StringLiteral(p)) => BoolLiteral(p.r.matches(s))
      case _                                    => ReMatch(subject, pattern)
    }
  }
}

// remove Formula trait here. BoolTerm is enough to represent

trait Equal extends BoolTerm, BoolBinOp

case class StringEqual(lhs: StringTerm, rhs: StringTerm) extends Equal {
  override def toString: String = s"$lhs == $rhs"
}

object StringEqual {
  def create(lhs: StringTerm, rhs: StringTerm): BoolTerm = {
    (lhs, rhs) match {
      case (StringLiteral(x), StringLiteral(y)) => BoolLiteral(x == y)
      case _                                    => StringEqual(lhs, rhs)
    }
  }
}

case class BoolEqual(lhs: BoolTerm, rhs: BoolTerm) extends Equal {
  override def toString: String = s"$lhs == $rhs"
}

object BoolEqual {
  def create(lhs: BoolTerm, rhs: BoolTerm): BoolTerm = {
    (lhs, rhs) match {
      case (BoolLiteral(x), BoolLiteral(y)) => BoolLiteral(x == y)
      case _                                => BoolEqual(lhs, rhs)
    }
  }
}

case class IntEqual(lhs: IntTerm, rhs: IntTerm) extends Equal {
  override def toString: String = s"$lhs == $rhs"
}

object IntEqual {
  def create(lhs: IntTerm, rhs: IntTerm): BoolTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => BoolLiteral(x == y)
      case _                              => IntEqual(lhs, rhs)
    }
  }
}

case class IntLess(lhs: IntTerm, rhs: IntTerm) extends BoolBinOp {
  override def toString: String = s"$lhs < $rhs"
}

object IntLess {
  def create(lhs: IntTerm, rhs: IntTerm): BoolTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => BoolLiteral(x < y)
      case _                              => IntLess(lhs, rhs)
    }
  }
}

case class IntLessEqual(lhs: IntTerm, rhs: IntTerm) extends BoolBinOp {
  override def toString: String = s"$lhs <= $rhs"
}

object IntLessEqual {
  def create(lhs: IntTerm, rhs: IntTerm): BoolTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => BoolLiteral(x <= y)
      case _                              => IntLessEqual(lhs, rhs)
    }
  }
}

case class IntGreater(lhs: IntTerm, rhs: IntTerm) extends BoolBinOp {
  override def toString: String = s"$lhs > $rhs"
}

object IntGreater {
  def create(lhs: IntTerm, rhs: IntTerm): BoolTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => BoolLiteral(x > y)
      case _                              => IntGreater(lhs, rhs)
    }
  }
}

case class IntGreaterEqual(lhs: IntTerm, rhs: IntTerm) extends BoolBinOp {
  override def toString: String = s"$lhs >= $rhs"
}

object IntGreaterEqual {
  def create(lhs: IntTerm, rhs: IntTerm): BoolTerm = {
    (lhs, rhs) match {
      case (IntLiteral(x), IntLiteral(y)) => BoolLiteral(x >= y)
      case _                              => IntGreaterEqual(lhs, rhs)
    }
  }
}

case class And(args: Set[BoolTerm]) extends BoolTerm, HasOperands {
  override def operands: List[Term] = args.toList

  override def toString: String = s"and($args)"
}

object And {
  def create(args: Set[BoolTerm]): BoolTerm = {
    if (args.isEmpty)
      return DummyObject.unknownSymbol
    if (args.size == 1)
      return args.head
    // if there is a false literal, the result is false
    if (args.exists(a => a.is[BoolLiteral] && !a.as[BoolLiteral].value))
      return BoolLiteral(false)
    // if there is an unknown term, the result is unknown
    if (args.exists(_.is[DummyObject]))
      return DummyObject.unknownSymbol
    val groups = args.groupBy(x => x.is[BoolLiteral])
    val values = groups.map { case (isConcrete, group) =>
      if (isConcrete) BoolLiteral(group.map(x => x.as[BoolLiteral].value).foldLeft(true)(_ & _))
      else {
        if (group.size > 1) And(group)
        else group.head
      }
    }
    if (values.size == 1)
      values.head
    else
      And(values.toSet)
  }
}

case class Or(args: Set[BoolTerm]) extends BoolTerm, HasOperands {
  override def operands: List[Term] = args.toList

  override def toString: String = s"or($args)"
}

object Or {
  def create(args: Set[BoolTerm]): BoolTerm = {
    if (args.isEmpty)
      return DummyObject.unknownSymbol
    if (args.size == 1)
      return args.head
    // if there is a true literal, the result is true
    if (args.exists(a => a.is[BoolLiteral] && a.as[BoolLiteral].value))
      return BoolLiteral(true)
    // if there is an unknown term, the result is unknown
    if (args.exists(_.is[DummyObject]))
      return DummyObject.unknownSymbol
    val groups = args.groupBy(x => x.is[BoolLiteral])
    val values = groups.map { case (isConcrete, group) =>
      if (isConcrete) BoolLiteral(group.map(x => x.as[BoolLiteral].value).foldLeft(false)(_ | _))
      else {
        if (group.size > 1) Or(group)
        else group.head
      }
    }
    if (values.size == 1)
      values.head
    else
      Or(values.toSet)
  }
}

case class Not(arg: BoolTerm) extends BoolTerm, HasOperands {
  override def toString: String = s"not($arg)"

  override def operands: List[Term] = List(arg)
}

object Not {
  def create(arg: BoolTerm): BoolTerm = {
    arg match {
      case BoolLiteral(value) => BoolLiteral(!value)
      case _                  => Not(arg)
    }
  }
}
