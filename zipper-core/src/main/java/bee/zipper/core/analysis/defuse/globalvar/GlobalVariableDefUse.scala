package bee.zipper.core.analysis.defuse.globalvar

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XUtils}
import bee.zipper.core.analysis.defuse.XDefUse
import bee.zipper.core.analysis.graph.icfg.{DefaultICfg, LoopUnrolling}
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg

class GlobalVariableDefUse(val icfg: DefaultICfg, val reachingDefResult: ReachingDefResult, val utils: XUtils[String])
    extends XDefUse[String]

object GlobalVariableDefUse {
  def create(cpg: Cpg, vsa: ValueSetResult, iterations: Option[Int], enableIFDS: Boolean, lightweight: Boolean)(implicit
    ctx: AnalysisContext
  ): GlobalVariableDefUse = {
    ctx.cache.getOrElseUpdate(
      classOf[GlobalVariableDefUse],
      cpg, {
        // this class will modify ICFG, so we create a copy of it
        val icfg = DefaultICfg(cpg)
        // topological sorting will be used internally, so we should remove all back edges
        LoopUnrolling.unroll(icfg)
        val analysis = new GlobalVariableDefUseAnalysis(cpg, icfg, vsa, iterations, enableIFDS, lightweight)
        analysis.solve()
      }
    )
  }
}
