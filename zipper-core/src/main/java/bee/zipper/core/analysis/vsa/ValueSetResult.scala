package bee.zipper.core.analysis.vsa

import bee.zipper.api.solver.sym.term.{StringLiteral, SymbolicValue}
import bee.zipper.core.analysis.model.cs.PathCallGraph
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait ValueSetResult {
  def ptsOf(node: CfgNode, v: CfgNode, partialEval: Boolean = false)(implicit
    pathCallGraph: Option[PathCallGraph] = None
  ): Set[SymbolicValue]

  /** The implementation of ValueSetResult may cache the result of `ptsOf`. This method is used to clear the cache
    */
  def clear(): Unit
}

trait OnDemandValueSetResult extends ValueSetResult

object ValueSetResult {
  val dotPattern: String = ".*"

  def dotPatternSym: StringLiteral = StringLiteral(dotPattern)

  def isDotPattern(value: String): Boolean = value.matches("^(?:\\.\\*)+$")
}
