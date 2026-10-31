package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Conservatively proves that a probe can only receive constant values.
  *
  * The classification walks the def-use chain backwards (REACHING_DEF) inside the method:
  *   - a taint source (or anything derived from one) is `Tainted`;
  *   - literals and operators over constants are `Constant`;
  *   - parameters, unknown calls, globals and anything that cannot be proven are `Unknown`.
  *
  * Only probes classified as `Constant` are skipped: everything else is handed to the engine, so no tainted branch is
  * dropped. The per-node classification is memoized, which is the method-level index reused by all probes.
  */
object TaintProbePruner {
  sealed trait Origin
  case object Constant extends Origin
  case object Tainted  extends Origin
  case object Unknown  extends Origin
}

final class TaintProbePruner(sources: Set[CfgNode]) {
  import TaintProbePruner.*

  private val sourceIds = sources.map(_.id())
  private val memo      = mutable.Map.empty[Long, Origin]
  private val visiting  = mutable.Set.empty[Long]

  def isConstantOnly(probe: CfgNode): Boolean = classify(probe) == Constant

  def constantProbes(probes: List[CfgNode]): Set[Long] =
    probes.filter(isConstantOnly).map(_.id()).toSet

  private def classify(node: CfgNode): Origin =
    memo.getOrElse(
      node.id(), {
        if (sourceIds.contains(node.id())) Tainted
        else if (!visiting.add(node.id())) Unknown
        else {
          val result = compute(node)
          visiting.remove(node.id())
          memo(node.id()) = result
          result
        }
      }
    )

  private def compute(node: CfgNode): Origin =
    node match {
      case _: Literal => Constant
      case id: Identifier =>
        val definitions = id.in(EdgeTypes.REACHING_DEF).collectAll[CfgNode].toList
        combine(definitions.map(classify))
      case _: MethodParameterIn => Unknown
      case _: ControlStructure  => Unknown
      case _: MethodReturn      => Unknown
      case call: Call =>
        if (call.name.startsWith("<operator>.")) {
          val arguments = call.argument.toList
          combine(arguments.map(classify))
        } else Unknown // any real call may return tainted data
      case _ => Unknown
    }

  private def combine(origins: List[Origin]): Origin =
    if (origins.exists(_ == Tainted)) Tainted
    else if (origins.nonEmpty && origins.forall(_ == Constant)) Constant
    else Unknown
}
