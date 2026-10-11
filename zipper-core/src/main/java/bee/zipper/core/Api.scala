package bee.zipper.core

import bee.zipper.api.solver.sym.term.SymbolicValue
import bee.zipper.core.analysis.aliasing.AliasFinder
import bee.zipper.core.analysis.defuse.*
import bee.zipper.core.analysis.defuse.globalvar.*
import bee.zipper.core.analysis.defuse.mem.MemoryDefUse
import bee.zipper.core.analysis.graph.bbcfg.*
import bee.zipper.core.analysis.graph.cfg.DefaultCfg
import bee.zipper.core.analysis.graph.icfg.DefaultICfg
import bee.zipper.core.analysis.graph.vfg.{DefaultVfg, Vfg}
import bee.zipper.core.analysis.model.cs.PathCallGraph
import bee.zipper.core.analysis.model.summary.FunSummary
import bee.zipper.core.analysis.taint.{DefaultTaintAnalysis, TaintPath}
import bee.zipper.core.analysis.vsa.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}

object Api {
  def create(cpg: Cpg, enhancedValueSetAnalysis: Boolean = true)(implicit
    ctx: AnalysisContext = new AnalysisContext
  ): Api =
    new Api(cpg, enhancedValueSetAnalysis)
}

class Api(val cpg: Cpg, enhancedValueSetAnalysis: Boolean = true)(implicit val ctx: AnalysisContext) {
  lazy val vsa: OnDemandValueSetResult =
    if (enhancedValueSetAnalysis) DefaultSummaryValueSetResult(cpg)
    else WeakValueSetResult(vfg)

  def cfg(method: Method, unrolling: Boolean = false): DefaultCfg = DefaultCfg.create(method, unrolling)

  def bbCfg(method: Method, unrolling: Boolean = false): DefaultBBCfg = DefaultBBCfg.create(method, unrolling)

  def icfg(unrolling: Boolean = false): DefaultICfg = DefaultICfg.create(cpg, unrolling)

  def vfg: Vfg = DefaultVfg.create(cpg)

  def summary(method: Method, depth: Int = 1, maxDepth: Int = 3): FunSummary =
    FunSummary.create(method, depth, maxDepth)

  def pts(node: CfgNode, v: CfgNode, partialEval: Boolean = false)(implicit
    pathCallGraph: Option[PathCallGraph] = None
  ): Set[SymbolicValue] = vsa.ptsOf(node, v, partialEval)

  def clear(): Unit = ctx.cache.clear()

  def globalDefUse(
    iterations: Option[Int] = None,
    enableIFDS: Boolean = false,
    lightweight: Boolean = false
  ): GlobalVariableDefUse =
    GlobalVariableDefUse.create(cpg, vsa, iterations, enableIFDS, lightweight)

  def memoryDefUse(iterations: Option[Int] = None, enableIFDS: Boolean = false): MemoryDefUse =
    MemoryDefUse.create(cpg, vsa, iterations, enableIFDS)

  def doTaintAnalysis(
    strict: Boolean = true,
    exploitMode: Boolean = true,
    enableReachAnalysis: Boolean = false,
    enableDeduplicateFlow: Boolean = true,
    enableCustomSanitizer: Boolean = false,
    enableKeywordMatching: Boolean = false,
    enableIndirectSuperGlobalFetching: Boolean = true,
    aliasFinder: Option[AliasFinder] = None
  ): List[TaintPath] = {
    val taintAnalysis =
      DefaultTaintAnalysis(
        cpg,
        vfg,
        vsa,
        strict,
        exploitMode,
        enableReachAnalysis,
        enableDeduplicateFlow,
        enableCustomSanitizer,
        enableKeywordMatching,
        enableIndirectSuperGlobalFetching,
        aliasFinder
      )
    taintAnalysis.analyze().paths.toList
  }
}
