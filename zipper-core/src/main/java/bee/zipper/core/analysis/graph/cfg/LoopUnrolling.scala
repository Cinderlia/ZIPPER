package bee.zipper.core.analysis.graph.cfg

import bee.zipper.core.analysis.graph.LoopUnrollingBase
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

object LoopUnrolling extends LoopUnrollingBase[CfgEdge, DefaultCfg] {
  override def getControlStructures(cfg: DefaultCfg): Iterator[ControlStructure] = cfg.m.controlStructure

  override def createEdge(from: CfgNode, to: CfgNode): CfgEdge = DefaultCfgEdge(from, to)
}
