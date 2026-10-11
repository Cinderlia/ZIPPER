package bee.zipper.core.analysis.defuse.mem

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.ifds.HerosICfg
import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XReachingDef}
import bee.zipper.core.analysis.dataflow.reachingdef.mem.{IFDSMemoryReachingDef, MemoryReachingDef, MemoryUtils}
import bee.zipper.core.analysis.defuse.XDefUseAnalysis
import bee.zipper.core.analysis.graph.icfg.DefaultICfg
import bee.zipper.core.analysis.model.ptr.MemPtr
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg

class MemoryDefUseAnalysis(
  cpg: Cpg,
  icfg: DefaultICfg,
  vsa: ValueSetResult,
  iterations: Option[Int],
  enableIFDS: Boolean
)(implicit ctx: AnalysisContext)
    extends XDefUseAnalysis[MemPtr, MemoryDefUse](icfg) {
  override protected val utils = new MemoryUtils(cpg, vsa)

  override protected val reachingDefResult: ReachingDefResult = {
    if (enableIFDS) {
      val analysis = new IFDSMemoryReachingDef(HerosICfg(icfg), utils)
      analysis.analyze()
    } else {
      val analysis       = new MemoryReachingDef(icfg, utils, iterations)
      val dataflowResult = analysis.analyze()
      XReachingDef.toReachingDefResult(icfg, dataflowResult)
    }
  }

  override protected val defUse = new MemoryDefUse(icfg, reachingDefResult, utils)
}
