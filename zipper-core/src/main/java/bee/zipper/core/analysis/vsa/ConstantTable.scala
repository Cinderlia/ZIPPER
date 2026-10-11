package bee.zipper.core.analysis.vsa

import bee.zipper.api.solver.sym.term.SymbolicValue

import scala.collection.mutable

// TODO: consider the definition scope in the future
case class ConstantVariable(name: String)

type ConstantTable = mutable.MultiDict[ConstantVariable, SymbolicValue]

object ConstantTable {
  def empty: ConstantTable = mutable.MultiDict.empty
}
