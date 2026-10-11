package bee.zipper.api.solver.sym.term

trait StringTerm extends Term

trait StringBinOp extends StringTerm, BinOp

case class StringLiteral(value: String) extends ConstantValue, StringTerm {
  override def toString: String = value
}

case class StringVar(name: String) extends StringTerm, VarTerm {
  override def toString: String = s"s:$name"
}

trait ReplaceFamily extends StringTerm, HasOperands {
  def subject: StringTerm
  def pattern: StringTerm
  def replacement: StringTerm
  override def operands: List[Term] = List(subject, pattern, replacement)
}

case class Replace(subject: StringTerm, pattern: StringTerm, replacement: StringTerm) extends ReplaceFamily {
  override def toString: String = s"replace($subject, $pattern, $replacement)"
}

object Replace {
  def create(subject: StringTerm, pattern: StringTerm, replacement: StringTerm): StringTerm = {
    (subject, pattern, replacement) match {
      case (StringLiteral(s), StringLiteral(p), StringLiteral(r)) =>
        StringLiteral(s.replace(p, r))
      case _ =>
        Replace(subject, pattern, replacement)
    }
  }
}

case class ReplaceRe(subject: StringTerm, pattern: StringTerm, replacement: StringTerm) extends ReplaceFamily {
  override def toString: String =
    s"replace_re($subject, $pattern, $replacement)"
}

object ReplaceRe {
  def create(subject: StringTerm, pattern: StringTerm, replacement: StringTerm): StringTerm = {
    (subject, pattern, replacement) match {
      case (StringLiteral(s), StringLiteral(p), StringLiteral(r)) =>
        StringLiteral(p.r.replaceFirstIn(s, r))
      case _ =>
        ReplaceRe(subject, pattern, replacement)
    }
  }
}

case class ReplaceAll(subject: StringTerm, pattern: StringTerm, replacement: StringTerm) extends ReplaceFamily {
  override def toString: String =
    s"replace_all($subject, $pattern, $replacement)"
}

object ReplaceAll {
  def create(subject: StringTerm, pattern: StringTerm, replacement: StringTerm): StringTerm = {
    (subject, pattern, replacement) match {
      case (StringLiteral(s), StringLiteral(p), StringLiteral(r)) =>
        StringLiteral(s.replaceAll(p, r))
      case _ =>
        ReplaceAll(subject, pattern, replacement)
    }
  }
}

case class ReplaceAllRe(subject: StringTerm, pattern: StringTerm, replacement: StringTerm) extends ReplaceFamily {
  override def toString: String =
    s"replace_all_re($subject, $pattern, $replacement)"
}

object ReplaceAllRe {
  def create(subject: StringTerm, pattern: StringTerm, replacement: StringTerm): StringTerm = {
    (subject, pattern, replacement) match {
      case (StringLiteral(s), StringLiteral(p), StringLiteral(r)) =>
        StringLiteral(p.r.replaceAllIn(s, r))
      case _ =>
        ReplaceAllRe(subject, pattern, replacement)
    }
  }
}

case class SubString(subject: StringTerm, offset: IntTerm, length: IntTerm) extends StringTerm, HasOperands {
  override def toString: String = s"sub_string($subject, $offset, $length)"

  override def operands: List[Term] = List(subject, offset, length)
}

object SubString {
  def create(subject: StringTerm, offset: IntTerm, length: IntTerm): StringTerm = {
    (subject, offset, length) match {
      case (StringLiteral(s), IntLiteral(o), IntLiteral(l)) =>
        StringLiteral(s.substring(o.toInt, (o + l).toInt))
      case _ =>
        SubString(subject, offset, length)
    }
  }
}

case class StringConcat(lhs: StringTerm, rhs: StringTerm) extends StringBinOp {
  override def toString: String = s"$lhs + $rhs"
}

object StringConcat {
  def create(args: Iterable[StringTerm]): StringTerm = {
    args.toList match {
      case List(a1)     => a1
      case List(a1, a2) => create(a1, a2)
      case a1 :: tail   => create(a1, create(tail))
      case _            => assert(false)
    }
  }

  def create(lhs: StringTerm, rhs: StringTerm): StringTerm = {
    (lhs, rhs) match {
      case (StringLiteral(x), StringLiteral(y)) => StringLiteral(x + y)
      case _                                    => StringConcat(lhs, rhs)
    }
  }
}

case class FromInt(int: IntTerm) extends StringTerm, HasOperands {
  override def toString: String = s"fromInt($int)"

  override def operands: List[Term] = List(int)
}

object FromInt {
  def create(int: IntTerm): StringTerm = {
    int match {
      case IntLiteral(value) => StringLiteral(value.toString)
      case _                 => FromInt(int)
    }
  }
}
