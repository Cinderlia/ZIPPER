package bee.zipper.core.analysis.graph.vfg

import bee.zipper.util.graph.Edge
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait VfgEdge extends Edge[CfgNode] {
  def label: VfgLabel
}

trait VfgNormalEdge extends VfgEdge

trait VfgCallEdge extends VfgEdge

trait VfgRetEdge extends VfgEdge
