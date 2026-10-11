package bee.zipper.core.analysis.graph.icfg

import bee.zipper.util.graph.DefaultGraph
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait ICfg extends DefaultGraph[CfgNode, ICfgEdge]
