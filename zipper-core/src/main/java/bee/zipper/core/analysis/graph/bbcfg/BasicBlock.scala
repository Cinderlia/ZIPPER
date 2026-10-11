package bee.zipper.core.analysis.graph.bbcfg

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait BasicBlock {
  def setOrder(o: Int): Unit

  def order: Int

  def nodes: List[CfgNode]
}
