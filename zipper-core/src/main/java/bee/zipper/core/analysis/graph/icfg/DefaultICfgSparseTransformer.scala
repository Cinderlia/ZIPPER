package bee.zipper.core.analysis.graph.icfg

import bee.zipper.util.graph.SparseTransformer
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

class DefaultICfgSparseTransformer(graph: DefaultICfg, isMNode: CfgNode => Boolean)
    extends SparseTransformer[CfgNode, ICfgEdge](graph, isMNode) {
  override protected def newNormalEdge(from: CfgNode, to: CfgNode): ICfgEdge = ICfgNormalEdge(from, to)
}
