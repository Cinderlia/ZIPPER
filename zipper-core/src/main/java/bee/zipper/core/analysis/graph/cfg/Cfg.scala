package bee.zipper.core.analysis.graph.cfg

import bee.zipper.util.graph.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait Cfg extends DefaultGraph[CfgNode, CfgEdge] {
  def entry: CfgNode

  def exit: CfgNode
}
