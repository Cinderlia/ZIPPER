package bee.zipper.core.analysis.model.summary

import bee.zipper.api.solver.sym.extend.{ArraySideEffect, ObjectSideEffect, SymbolicObject}
import bee.zipper.api.solver.sym.term.SymbolicValue

import scala.collection.MultiDict

case class BlockSummary(
  dataflow: Map[String, SymbolicValue] = Map.empty,
  globalDefines: Set[String] = Set.empty,
  returnValue: Option[SymbolicValue] = None,
  objectCache: MultiDict[String, SymbolicObject] = MultiDict.empty,
  propertyWriteCache: MultiDict[String, ObjectSideEffect] = MultiDict.empty,
  arrayWriteCache: MultiDict[String, ArraySideEffect] = MultiDict.empty
)

object BlockSummary {
  lazy val empty: BlockSummary = BlockSummary()
}
