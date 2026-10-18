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
  enableControlStructure: Boolean = false,
  emitControlFlowPaths: Boolean = false,
  rawPathEmitter: Option[TaintPath => Unit] = None
) extends TaintAnalysis {
  private val language   = cpg.metaData.language.head
  private val pathFilter = new PathFilter(cpg, vsa, language, exploitMode, enableCustomSanitizer, enableKeywordMatching)
  private val controlStructurePathEnhancer = new ControlStructurePathEnhancer
  private val taintSourceNodes = sources.toSet
  private val controlDependencyExtractor = new ControlDependencyExtractor(cpg)

  override def analyze(): TaintAnalysisResult = {
    require(!emitControlFlowPaths || rawPathEmitter.nonEmpty, "Raw control-flow path output requires an emitter")
    implicit val context: EngineContext = {
      val semantic = SemanticsGenerator.taintSemantic(language, exploitMode)
      semantic.initialize(cpg)
      EngineContext(
        semantic,
        EngineConfig(maxArgsToAllow = 3000, strict = strict, exploitMode = exploitMode, aliasFinder = aliasFinder)
      )
    }

    if (emitControlFlowPaths) {
      kindToSinks.foreach { case (kind, taintSinks) =>
        val (sinks, _) = extractSinks(taintSinks)
        sinks.reachableByFlows(sources).foreach { flow =>
          val path = TaintPath.withControlDependencies(kind, true, extractCfgNodes(flow), controlDependencyExtractor)
          rawPathEmitter.foreach(_(path))
        }
      }
      return TaintAnalysisResult(Iterator.empty, context.newDataflowEdges)
    }

    // iterate over each vulnerability kind and its associated sinks to compute taint paths.
    val paths = kindToSinks.iterator.flatMap { case (kind, taintSinks) =>
      val (sinks, argumentToCall) = extractSinks(taintSinks)
      // step1. joern taint engine entrypoint
      val flows =
        sinks
          .reachableByFlows(sources)
          .map(path => refactorPath(path, argumentToCall)) // refactor paths by appending real sink nodes if needed
      // step2. remove duplicate flows if exploit mode is disabled
      val deduplicated = if (!exploitMode && enableDeduplicateFlow) DuplicateFlowProcessor.deduplicate(flows) else flows
      // step3. transform joern `Path` into `TaintPath`
      val taintPaths = deduplicated.map { path =>
        val originalPath = extractCfgNodes(path)
        val basePath = TaintPath(kind, true, originalPath)
        val enhancedPath =
          if (enableControlStructure) controlStructurePathEnhancer.enhance(basePath, taintSourceNodes)
          else basePath
        TaintPath.withControlDependencies(
          kind,
          true,
          enhancedPath.path,
          controlDependencyExtractor,
          originalPath.toSet
        )
      }
      // step4. filter out invalid paths
      val validatedPaths = taintPaths.filter(path => pathFilter.isValid(path))
      // step5. filter paths based on lightweight path-reachability
      if (enableReachAnalysis) validatedPaths.filter(path => pathFilter.isReachable(path)) else validatedPaths
    }

    TaintAnalysisResult(paths, context.newDataflowEdges)
  }

  /** extract the sink nodes in CPG and builds a mapping from argument nodes to their corresponding calls
    */
  private def extractSinks(taintSinks: List[TaintSink]): (List[CfgNode], Map[CfgNode, CfgNode]) = {
    val sinks = taintSinks.flatMap {
      case DirectNodeSink(node)           => List(node)
      case CallArgumentSink(_, arguments) => arguments
    }
    val argumentToCall = taintSinks
      .collect { case CallArgumentSink(call, arguments) => arguments.map(_ -> call) }
      .flatten
      .toMap
    (sinks, argumentToCall)
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
    enableControlStructure: Boolean = false,
    emitControlFlowPaths: Boolean = false,
    rawPathEmitter: Option[TaintPath => Unit] = None
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
      enableControlStructure,
      emitControlFlowPaths,
      rawPathEmitter
    )
  }
}
