package bee.zipper.core.analysis.defuse.globalvar

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.ifds.HerosICfg
import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XReachingDef}
import bee.zipper.core.analysis.dataflow.reachingdef.globalvar.*
import bee.zipper.core.analysis.defuse.XDefUseAnalysis
import bee.zipper.core.analysis.graph.icfg.*
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

class GlobalVariableDefUseAnalysis(
  cpg: Cpg,
  icfg: DefaultICfg,
  vsa: ValueSetResult,
  iterations: Option[Int],
  enableIFDS: Boolean,
  lightweight: Boolean
)(implicit ctx: AnalysisContext)
    extends XDefUseAnalysis[String, GlobalVariableDefUse](icfg) {
  override protected val utils = new GlobalVariableUtils(cpg, vsa, lightweight)

  override protected val reachingDefResult: ReachingDefResult = {
    if (enableIFDS) {
      val analysis = new IFDSGlobalVariableReachingDef(HerosICfg(icfg), utils)
      analysis.analyze()
    } else {
      pruneICfg(icfg)
      val analysis       = new GlobalVariableReachingDef(icfg, utils, iterations)
      val dataflowResult = analysis.analyze()
      XReachingDef.toReachingDefResult(icfg, dataflowResult)
    }
  }

  /** Remove the call/return edges that may introduce false positive because of the context-insensitive analysis
    */
  private def pruneICfg(icfg: DefaultICfg, threshold: Int = 2): Unit = {
    // callee -> call edges reaching callee
    val mToCallerEdges = mutable.MultiDict.from(icfg.getEdges.collect { case e: ICfgCallEdge => e.to.method -> e })
    // callee -> ret edges reaching caller
    val mToRetEdges = mutable.MultiDict.from(icfg.getEdges.collect { case e: ICfgRetEdge => e.from.method -> e })
    mToRetEdges.keySet.foreach {
      case m if m.name != "<global>" && mToRetEdges.get(m).size > threshold =>
        // remove call and return edges
        mToRetEdges.get(m).foreach(e => icfg.removeEdge(e))
        mToCallerEdges.get(m).foreach(icfg.removeEdge)
      case _ =>
    }
  }

  override protected val defUse = new GlobalVariableDefUse(icfg, reachingDefResult, utils)
}
