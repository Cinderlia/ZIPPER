package bee.zipper.core.ir

import io.shiftleft.codepropertygraph.generated.nodes.Method

trait Expr

trait LValue extends Expr

trait RValue extends Expr

trait Var extends LValue with RValue {
  def name: String
}

/** created by `Identifier` cpg node
  */
case class RealVar(name: String, container: Method) extends Var {
  override def toString: String = s"${container.id}:$name"
}

/** created by the cpg node that can procedure a value
  */
case class TmpVar(name: String, container: Method) extends Var {
  override def toString: String = s"${container.id}:$name"
}

case class StaticFieldVar(typeFullName: String, field: String) extends Var {
  override def name: String = s"$typeFullName::$field"

  override def toString: String = s"$typeFullName::$field"
}

case class InstanceFieldAccess(base: Var, field: Var) extends LValue with RValue {
  override def toString: String = s"$base->$field"
}

/** created by the `Call` cpg node whose name is `indexAccess`
  */
case class ArrayAccess(base: Var, index: Var) extends LValue with RValue {
  override def toString: String = s"$base[$index]"
}
