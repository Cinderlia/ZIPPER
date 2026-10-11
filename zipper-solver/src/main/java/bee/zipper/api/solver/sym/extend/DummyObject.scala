package bee.zipper.api.solver.sym.extend

import bee.zipper.api.solver.sym.term.{BoolTerm, IntTerm, StringTerm}

/** Placeholder for unresolved symbolic expression in VSA process.
  *
  * Use Cases:
  *   - Used for alias analysis when we cannot find the declaration of one variable.
  *   - Represent an unknown value explicitly. In Feasibility Analysis, we always treat the branch whose condition
  *     expression can't be evaluated as feasible.
  */
case class DummyObject(name: String) extends SymbolicMap, IntTerm, StringTerm, BoolTerm {
  override def toString: String = s"dummy: $name $concrete"
}

object DummyObject {

  /** A dummy object for representing an unknown value explicitly
    */
  val unknownSymbol: DummyObject = DummyObject("unknown")
}
