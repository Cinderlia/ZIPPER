package bee.zipper.core.analysis.aliasing

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

/** on-demand alias analysis
  */
trait AliasFinder {

  /** Given a memory access node, find the aliases on it
    */
  def find(node: CfgNode): List[CfgNode]
}
