package bee.zipper.core.analysis.graph.icfg

import bee.zipper.util.graph.Edge
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Method}

trait ICfgEdge extends Edge[CfgNode]

case class ICfgNormalEdge(from: CfgNode, to: CfgNode) extends ICfgEdge

case class ICfgCallEdge(from: CfgNode, to: CfgNode, callee: Method) extends ICfgEdge

case class ICfgCallToReturnEdge(from: CfgNode, to: CfgNode) extends ICfgEdge

case class ICfgRetEdge(from: CfgNode, to: CfgNode, callsite: Call) extends ICfgEdge
