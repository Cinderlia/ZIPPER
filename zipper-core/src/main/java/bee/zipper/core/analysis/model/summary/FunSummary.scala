package bee.zipper.core.analysis.model.summary

import bee.zipper.api.solver.sym.extend.{ObjectSideEffect, SymbolicObject}
import bee.zipper.api.solver.sym.term.SymbolicValue
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.bbcfg.*
import bee.zipper.util.AnyExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.Method

import scala.collection.MultiDict

case class FunSummary(
  blockSummaries: Map[BasicBlock, BlockSummary] = Map.empty,
  parameters: List[String] = List.empty,
  returnValues: Set[SymbolicValue] = Set.empty,
  parameterSideEffects: MultiDict[Int, SymbolicValue] = MultiDict.empty,
  globalSideEffects: MultiDict[String, SymbolicValue] = MultiDict.empty,
  objectCache: MultiDict[String, SymbolicObject] = MultiDict.empty,
  propertyWriteCache: MultiDict[String, ObjectSideEffect] = MultiDict.empty
)

object FunSummary {
  lazy val empty: FunSummary = FunSummary()

  def create(method: Method, depth: Int = 1, maxDepth: Int = 3)(implicit ctx: AnalysisContext): FunSummary = {
    ctx.cache.getOrElseUpdate(
      classOf[FunSummary],
      method, {
        try {
          val builder = new DefaultFunSummaryBuilder(method, depth, maxDepth)
          builder.build()
        } catch {
          case e: IllegalStateException =>
            println("[*] warning: summaryOf IllegalStateException")
            FunSummary.empty
        }
      }
    )
  }
}
