package bee.zipper.core.analysis.graph.icfg

import bee.zipper.core.analysis.graph.LoopUnrollingBase
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, ControlStructure}
import io.shiftleft.semanticcpg.language.*

object LoopUnrolling extends LoopUnrollingBase[ICfgEdge, DefaultICfg] {
  override def getControlStructures(icfg: DefaultICfg): Iterator[ControlStructure] =
    icfg.getReachableMethods.controlStructure

  override def createEdge(from: CfgNode, to: CfgNode): ICfgEdge = ICfgNormalEdge(from, to)
}
