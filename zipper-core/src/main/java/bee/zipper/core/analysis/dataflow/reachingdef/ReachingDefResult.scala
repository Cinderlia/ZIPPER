package bee.zipper.core.analysis.dataflow.reachingdef

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

/** Unified representation of the results of reaching-def analysis
  */
class ReachingDefResult(stmtToReachingDefs: Map[CfgNode, List[CfgNode]]) {
  def getReachingDefs(stmt: CfgNode): List[CfgNode] =
    stmtToReachingDefs.getOrElse(stmt, List.empty)
}
