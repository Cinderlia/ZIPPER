package bee.zipper.core.analysis.graph.cfg

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

case class DefaultCfgEdge(from: CfgNode, to: CfgNode) extends CfgEdge
