package bee.zipper.core.analysis.defuse.mem

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XUtils}
import bee.zipper.core.analysis.defuse.XDefUse
import bee.zipper.core.analysis.graph.icfg.{DefaultICfg, LoopUnrolling}
import bee.zipper.core.analysis.model.ptr.MemPtr
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg

class MemoryDefUse(val icfg: DefaultICfg, val reachingDefResult: ReachingDefResult, val utils: XUtils[MemPtr])
    extends XDefUse[MemPtr]

object MemoryDefUse {
  def create(cpg: Cpg, vsa: ValueSetResult, iterations: Option[Int], enableIFDS: Boolean)(implicit
    ctx: AnalysisContext
  ): MemoryDefUse = {
    ctx.cache.getOrElseUpdate(
      classOf[MemoryDefUse],
      cpg, {
        // this class will modify ICFG, so we create a copy of it
        val icfg = DefaultICfg(cpg)
        LoopUnrolling.unroll(icfg)
        val analysis = new MemoryDefUseAnalysis(cpg, icfg, vsa, iterations, enableIFDS)
        analysis.solve()
      }
    )
  }
}
