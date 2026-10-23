package bee.zipper.core.analysis.taint

import bee.zipper.core.analysis.aliasing.AliasFinder
import bee.zipper.core.analysis.graph.vfg.Vfg
import bee.zipper.core.analysis.taint.*
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.semantic.SemanticsGenerator
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

/** @param sources
  *   the list of nodes in the CPG that are considered as taint sources
  * @param kindToSinks
  *   a map from vulnerability kinds to their associated taint sinks
  */
class DefaultTaintAnalysis(
  cpg: Cpg,
  sources: List[CfgNode],
  kindToSinks: Map[String, List[TaintSink]],
  vsa: ValueSetResult,
  strict: Boolean = true,
  exploitMode: Boolean = true,
  enableReachAnalysis: Boolean = false,
  enableDeduplicateFlow: Boolean = true,
  enableCustomSanitizer: Boolean = false,
  enableKeywordMatching: Boolean = false,
  aliasFinder: Option[AliasFinder] = None,
  enableControlStructure: Boolean = false
) extends TaintAnalysis {
  private val language   = cpg.metaData.language.head
  private val pathFilter = new PathFilter(cpg, vsa, language, exploitMode, enableCustomSanitizer, enableKeywordMatching)
  private val controlStructurePathEnhancer = new ControlStructurePathEnhancer
  private val taintControlFlowProvenance   = new TaintControlFlowProvenance(sources.toSet)
  private val taintSourceNodes             = sources.toSet
  private val emptySinkTracer = new EmptySinkControlFlowTracer(taintSourceNodes, taintControlFlowProvenance)
  private val sinkGroupMerger = new SinkGroupMerger

  override def analyze(): TaintAnalysisResult = {
    implicit val context: EngineContext = {
      val semantic = SemanticsGenerator.taintSemantic(language, exploitMode)
      semantic.initialize(cpg)
      EngineContext(
        semantic,
        EngineConfig(maxArgsToAllow = 3000, strict = strict, exploitMode = exploitMode, aliasFinder = aliasFinder)
      )
    }

    // iterate over each vulnerability kind and its associated sinks to compute taint paths.
    val paths = kindToSinks.iterator.flatMap { case (kind, taintSinks) =>
      val extractedSinks = extractSinks(taintSinks)
      // step1. joern taint engine entrypoint
      val flows =
        extractedSinks.probes
          .reachableByFlows(sources)
          .map(path =>
            refactorPath(path, extractedSinks.argumentToCall)
          ) // refactor paths by appending real sink nodes if needed
      // step2. remove duplicate flows if exploit mode is disabled
      val deduplicated = if (!exploitMode && enableDeduplicateFlow) DuplicateFlowProcessor.deduplicate(flows) else flows
      // step3. transform joern `Path` into `TaintPath`
      val taintPaths = deduplicated.map(path => TaintPath(kind, true, extractCfgNodes(path)))
      // step4. enhance taint paths with the control structures that guard or depend on them
      val enhancedPaths = taintPaths.map { path =>
        if (enableControlStructure) {
          val selectedControlPath = controlStructurePathEnhancer.enhance(path, taintSourceNodes)
          taintControlFlowProvenance.enhance(selectedControlPath)
        } else path
      }
      // step5. in control-structure mode, also keep sinks that receive no taint: their path is the sink itself
      val collectedPaths =
        if (enableControlStructure) {
          val taintedPaths = enhancedPaths.toList
          (taintedPaths ++ untaintedSinkPaths(kind, extractedSinks.sinks, taintedPaths)).iterator
        } else enhancedPaths
      // step6. filter out invalid paths
      val validatedPaths = collectedPaths.filter(path => pathFilter.isValid(path))
      // step7. merge sinks that share a straight-line CFG segment, reporting their paths together
      val segmentPaths =
        if (enableControlStructure) sinkGroupMerger.merge(validatedPaths.toList).iterator else validatedPaths
      // step8. filter paths based on lightweight path-reachability
      if (enableReachAnalysis) segmentPaths.filter(path => pathFilter.isReachable(path)) else segmentPaths
    }

    TaintAnalysisResult(paths, context.newDataflowEdges)
  }

  /** the nodes needed to run the taint engine for a set of sinks
    *
    * @param probes
    *   nodes handed to the taint engine, i.e. the arguments of a call sink or a direct sink node
    * @param argumentToCall
    *   maps an argument probe to the real sink, i.e. its enclosing call
    * @param sinks
    *   real sink nodes, i.e. the endpoints of the resulting taint paths
    */
  private case class ExtractedSinks(probes: List[CfgNode], argumentToCall: Map[CfgNode, CfgNode], sinks: List[CfgNode])

  /** extract the sink nodes in CPG and builds a mapping from argument nodes to their corresponding calls
    */
  private def extractSinks(taintSinks: List[TaintSink]): ExtractedSinks = {
    val probes = taintSinks.flatMap {
      case DirectNodeSink(node)           => List(node)
      case CallArgumentSink(_, arguments) => arguments
    }
    val argumentToCall = taintSinks
      .collect { case CallArgumentSink(call, arguments) => arguments.map(_ -> call) }
      .flatten
      .toMap
    val sinks = taintSinks.map {
      case DirectNodeSink(node)      => node
      case CallArgumentSink(call, _) => call
    }.distinct
    ExtractedSinks(probes, argumentToCall, sinks)
  }

  /** builds paths for sinks that no taint flow reaches
    *
    * This is only used in control-structure mode, where every sink is reported even if it has no tainted input. A sink
    * is considered untainted when it is not the endpoint of any taint path collected for the same vulnerability kind.
    * For such a sink we try to reconstruct the guard that explains it: walking the CFG backwards, the nearest enclosing
    * control structure with a tainted condition contributes its provenance, so the path becomes `source ... ->
    * condition -> control structure -> sink`. When no guard is tainted the path stays the sink itself.
    */
  private def untaintedSinkPaths(kind: String, sinks: List[CfgNode], taintedPaths: List[TaintPath]): List[TaintPath] = {
    val taintedSinks = taintedPaths.map(_.sink).toSet
    sinks
      .filterNot(taintedSinks.contains)
      .map(sink => emptySinkPath(kind, sink, taintedPaths))
  }

  /** builds the path of a single sink that no taint flow reaches
    *
    * The reconstructed path goes through the guard, but it still has to pass the sanitizer checks. When it does not,
    * the sink is kept as a single-node path: control-structure mode reports every sink, and dropping it entirely would
    * lose the coverage that the empty-sink handling exists for.
    *
    * @see
    *   [[untaintedSinkPaths]]
    */
  private def emptySinkPath(kind: String, sink: CfgNode, taintedPaths: List[TaintPath]): TaintPath = {
    val singleNodePath = TaintPath(kind, true, List(sink))
    emptySinkTracer
      .trace(sink, taintedPaths)
      .map(nodes => taintControlFlowProvenance.enhance(TaintPath(kind, true, nodes)))
      .filter(pathFilter.isValid)
      .getOrElse(singleNodePath)
  }

  /** refactor a path by appending the real sink node if it exists in given map
    */
  private def refactorPath(path: Path, argumentToCall: Map[CfgNode, CfgNode]): Path = {
    argumentToCall.get(path.elements.last.asInstanceOf[CfgNode]) match {
      case Some(realSink) => Path(path.elements :+ realSink)
      case None           => path
    }
  }

  private def extractCfgNodes(path: Path): List[CfgNode] = path.elements.collect { case node: CfgNode => node }
}

object DefaultTaintAnalysis {

  /** wrapper for creating a default taint analysis instance without handling sources/sinks
    */
  def apply(
    cpg: Cpg,
    vfg: Vfg,
    vsa: ValueSetResult,
    strict: Boolean = true,
    exploitMode: Boolean = true,
    enableReachAnalysis: Boolean = false,
    enableDeduplicateFlow: Boolean = true,
    enableCustomSanitizer: Boolean = false,
    enableKeywordMatching: Boolean = false,
    enableIndirectSuperGlobalFetching: Boolean = true,
    aliasFinder: Option[AliasFinder] = None,
    enableControlStructure: Boolean = false
  ): DefaultTaintAnalysis = {
    val sources = {
      val searcher =
        TaintSourceSearcher.create(cpg, vfg, enableWrapperFinder = false, enableIndirectSuperGlobalFetching)
      searcher.search()._1
    }
    val sinks = {
      val searcher = TaintSinkSearcher.create(cpg, vsa)
      searcher.search()
    }
    new DefaultTaintAnalysis(
      cpg,
      sources,
      sinks,
      vsa,
      strict,
      exploitMode,
      enableReachAnalysis,
      enableDeduplicateFlow,
      enableCustomSanitizer,
      enableKeywordMatching,
      aliasFinder,
      enableControlStructure
    )
  }
}
