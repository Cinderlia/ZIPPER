package bee.zipper.core.analysis.graph.bbcfg

import bee.zipper.util.graph.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait BBCfg extends DefaultGraph[BasicBlock, BBEdge] {
  def entry: BasicBlock

  def exit: BasicBlock

  def bbOf(node: CfgNode): BasicBlock
}
