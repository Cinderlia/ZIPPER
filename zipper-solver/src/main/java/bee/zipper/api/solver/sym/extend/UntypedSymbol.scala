package bee.zipper.api.solver.sym.extend

import bee.zipper.api.solver.sym.term.*

/* symbols for summary-based analysis */

/** represented the value of a variable
  */
case class UntypedVariable(name: SymbolicValue) extends SymbolicValue {
  override def toString: String = name.toString
}

/** represented the value of an array read operation
  */
case class UntypedArrayFetch(base: SymbolicValue, key: SymbolicValue) extends SymbolicValue {
  override def toString: String = s"$base[$key]"
}

/** The side effect operation on object or array
  */
trait SideEffect extends SymbolicValue

trait ObjectSideEffect extends SideEffect

trait ArraySideEffect extends SideEffect

/** wrapper symbol for array write operation. the index in block summary is the name of the array
  */
case class ArrayWriteWrapper(key: SymbolicValue, data: SymbolicValue) extends ArraySideEffect {
  override def toString: String = s"wrapper(X[$key] = $data)"
}

/** represented all keys of an array. This class is used to model statements related to array traversal (such as
  * `foreach` statement in PHP)
  */
case class ArrayAllKeys(base: SymbolicValue) extends SymbolicValue

/** represented all values of an array. See [[ArrayAllKeys]].
  */
case class ArrayAllValues(base: SymbolicValue) extends SymbolicValue

/** Symbol for `array_push` builtin function in PHP
  */
case class ArrayPush(base: SymbolicValue, value: SymbolicValue) extends ArraySideEffect

/** represented the value of a property read operation
  */
case class UntypedPropertyFetch(base: SymbolicValue, key: SymbolicValue) extends SymbolicValue {
  override def toString: String = s"$base->$key"
}

/** wrapper symbol for property write operation (similar with array write operation)
  */
case class PropertyWriteWrapper(key: SymbolicValue, data: SymbolicValue) extends ObjectSideEffect {
  override def toString: String = s"wrapper(X->$key = $data)"
}

/** represented the value of a string concat operation
  */
case class UntypedStringConcat(lhs: SymbolicValue, rhs: SymbolicValue) extends StringTerm {
  override def toString: String = s"$lhs + $rhs"
}

object UntypedStringConcat {
  def apply(args: Iterable[SymbolicValue]): UntypedStringConcat = {
    args.toList match {
      case List(a1, a2) => UntypedStringConcat(a1, a2)
      case a1 :: tail   => UntypedStringConcat(a1, apply(tail))
      case _            => assert(false)
    }
  }
}

case class MultiValue(values: List[SymbolicValue]) extends SymbolicValue {
  override def toString: String = s"[${values.mkString(", ")}]"
}

object MultiValue {
  def apply(values: SymbolicValue*): MultiValue = MultiValue(values.toList)
}

case class UntypedAdd(lhs: SymbolicValue, rhs: SymbolicValue) extends IntTerm {
  override def toString: String = s"$lhs + $rhs"
}

case class UntypedSub(lhs: SymbolicValue, rhs: SymbolicValue) extends IntTerm {
  override def toString: String = s"$lhs - $rhs"
}

case class UntypedEqual(lhs: SymbolicValue, rhs: SymbolicValue) extends BoolTerm {
  override def toString: String = s"$lhs == $rhs"
}

case class UntypedLogicalNot(value: SymbolicValue) extends BoolTerm {
  override def toString: String = s"!$value"
}

case class UntypedLogicalAnd(lhs: SymbolicValue, rhs: SymbolicValue) extends BoolTerm {
  override def toString: String = s"$lhs && $rhs"
}

case class UntypedLogicalOr(lhs: SymbolicValue, rhs: SymbolicValue) extends BoolTerm {
  override def toString: String = s"$lhs || $rhs"
}
