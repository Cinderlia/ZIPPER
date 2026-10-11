package bee.zipper.core.analysis.graph.vfg

import bee.zipper.util.graph.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait Vfg extends DefaultGraph[CfgNode, VfgEdge]
