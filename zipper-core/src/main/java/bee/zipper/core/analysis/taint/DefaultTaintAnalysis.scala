package bee.zipper.core.analysis.taint

import bee.zipper.core.analysis.aliasing.AliasFinder
import bee.zipper.core.analysis.graph.vfg.Vfg
import bee.zipper.core.analysis.taint.*
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.php.passes.UnresolvedCallRegistry
import bee.zipper.core.semantic.SemanticsGenerator
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext, TableEntry, TaskFingerprint}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
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
  enableImplicitTaint: Boolean = false,
  includeUntaintedSinks: Boolean = true
) extends TaintAnalysis {
  private val language   = cpg.metaData.language.head
  private val pathFilter = new PathFilter(cpg, vsa, language, exploitMode, enableCustomSanitizer, enableKeywordMatching)
  private val controlStructurePathEnhancer = new ControlStructurePathEnhancer
  private val taintControlFlowProvenance   = new TaintControlFlowProvenance(sources.toSet)
  private val taintSourceNodes             = sources.toSet
  private val emptySinkTracer       = new EmptySinkControlFlowTracer(taintSourceNodes, taintControlFlowProvenance)
  private val sinkGroupMerger       = new SinkGroupMerger
  private val implicitTaintEnhancer = new ImplicitTaintEnhancer(emptySinkTracer)
  private val logger                = org.slf4j.LoggerFactory.getLogger(this.getClass)
  private val traceOrigins          = java.lang.Boolean.getBoolean("zipper.taint.traceOrigins")
  private val traceDeclarations     = java.lang.Boolean.getBoolean("zipper.taint.traceDeclarations")

  private def locationOf(node: CfgNode): String =
    s"${node.file.headOption.map(_.name).getOrElse("?")}:${node.lineNumber.getOrElse(-1)}"

  private def traceAdded(origin: String, before: Set[Long], after: TaintPath): TaintPath = {
    if (traceOrigins)
      after.path.filterNot(node => before.contains(node.id())).foreach { node =>
        logger.info(
          s"[origin] $origin ${node.getClass.getSimpleName} ${locationOf(node)} " +
            node.code.linesIterator.mkString(" ").take(80)
        )
      }
    after
  }

  override def analyze(): TaintAnalysisResult = {
    implicit val context: EngineContext = {
      val semantic = SemanticsGenerator.taintSemantic(language, exploitMode)
      semantic.initialize(cpg)
      EngineContext(
        semantic,
        EngineConfig(
          maxArgsToAllow = 3000,
          strict = strict,
          exploitMode = exploitMode,
          aliasFinder = aliasFinder,
          narrowUnresolvedCalls = java.lang.Boolean.getBoolean("zipper.taint.narrowUnresolved")
        )
      )
    }

    // optional reusable result table: engine results computed for one probe are reused by later probes
    val sharedTable =
      if (java.lang.Boolean.getBoolean("zipper.taint.sharedTable"))
        Some(
          new io.joern.dataflowengineoss.queryengine.SharedResultTable(
            Integer.getInteger("zipper.taint.sharedTable.max", 200000).intValue()
          )
        )
      else None

    val probeContext: EngineContext = context.copy(config = context.config.copy(sharedTable = sharedTable))

    // iterate over each vulnerability kind and its associated sinks to compute taint paths.
    val paths = kindToSinks.iterator.flatMap { case (kind, taintSinks) =>
      val extractedSinks = extractSinks(taintSinks)
      // step1. joern taint engine entrypoint
      val flows = extractedSinks.probes
        .reachableByFlows(sources)(probeContext)
        .map(path => refactorPath(path, extractedSinks.argumentToCall))
        .toList // refactor paths by appending real sink nodes if needed
      // step2. remove duplicate flows if exploit mode is disabled
      val deduplicated = if (!exploitMode && enableDeduplicateFlow) DuplicateFlowProcessor.deduplicate(flows) else flows
      // step3. transform joern `Path` into `TaintPath`
      val taintPaths = deduplicated.map { path =>
        val nodes = extractCfgNodes(path)
        val taint =
          TaintPath(kind, true, nodes, nodes.lastOption, dataflowNodes = nodes.map(_.id()).toSet)
        if (traceOrigins)
          taint.path.foreach(node =>
            logger.info(s"[origin] dataflow ${node.getClass.getSimpleName} ${locationOf(node)}")
          )
        taint
      }.toList
      // step4. enhance taint paths with the control structures that guard or depend on them
      val enhancedPaths = taintPaths.map { path =>
        if (enableControlStructure) {
          val beforeControl  = path.path.map(_.id()).toSet
          val controlPath    = controlStructurePathEnhancer.enhance(path, taintControlFlowProvenance)
          val withControl    = traceAdded("control-structure", beforeControl, controlPath)
          val beforeProv     = withControl.path.map(_.id()).toSet
          val provenancePath = taintControlFlowProvenance.enhance(withControl)
          traceAdded("control-provenance", beforeProv, provenancePath)
        } else path
      }.toList
      // step5. drop sanitized/invalid taint paths. In control-structure mode the default path filter is
      //        bypassed on purpose: the appended control-flow slices contain guards such as `$x != ""`,
      //        whose comparison calls are configured as type sanitizers and would reject paths that are
      //        in fact tainted. Dedicated sanitizer handling for this mode is added separately.
      val validatedTaintPaths =
        if (enableControlStructure) enhancedPaths else enhancedPaths.filter(path => pathFilter.isValid(path))
      // step6. in control-structure mode, also keep sinks that receive no taint: their path is the sink itself
      val collectedPaths: List[TaintPath] =
        if (enableControlStructure && includeUntaintedSinks) {
          val empty = untaintedSinkPaths(kind, extractedSinks.sinks, enhancedPaths)
          if (traceOrigins)
            empty.filterNot(path => enhancedPaths.exists(_.sink.id() == path.sink.id())).foreach { path =>
              logger.info(s"[origin] empty-sink ${locationOf(path.sink)}")
            }
          enhancedPaths ++ empty
        } else enhancedPaths
      // step7. merge sinks that share a straight-line CFG segment, reporting their paths together
      val mergedPaths =
        if (enableControlStructure) sinkGroupMerger.merge(collectedPaths) else collectedPaths
      // step8. add the implicit taint of flags that are assigned under a tainted guard
      val implicitPaths =
        if (enableControlStructure && enableImplicitTaint)
          mergedPaths.map { path =>
            val before = path.path.map(_.id()).toSet
            traceAdded("implicit-taint", before, implicitTaintEnhancer.enhance(path, mergedPaths))
          }
        else mergedPaths
      // step9. filter paths based on lightweight path-reachability
      if (enableReachAnalysis) implicitPaths.filter(path => pathFilter.isReachable(path)) else implicitPaths
    }

    // Control-flow enhancement may pull statements from later, unrelated blocks when a variable is reused
    // (`$stmt`/`$rows` reused by a second query). Keep only nodes that can precede the sink in the CFG; a path whose
    // source cannot precede the sink in the same method is dropped.
    val prunedPaths =
      (if (!enableControlStructure) paths
       else
         paths.flatMap { path =>
           val sink = path.sink
           if (path.path.head.method.id() == sink.method.id() && !cfgReaches(path.path.head, sink)) None
           else {
             // control structures are not CFG nodes in joern; keep them for the guard analysis below
             Some(
               path.copy(path =
                 path.path.filter(node =>
                   node.id() == sink.id() || node.isInstanceOf[ControlStructure] || cfgReaches(node, sink)
                 )
               )
             )
           }
         }).toList

    if (traceDeclarations)
      prunedPaths.foreach { path =>
        path.path.foreach {
          case parameter: MethodParameterIn =>
            logger.info(
              s"[decl] final MethodParameterIn ${locationOf(parameter)} method=${parameter.method.name} code=${parameter.code}"
            )
          case node: Method =>
            logger.info(s"[decl] final Method ${locationOf(node)} ${node.name}")
          case _ =>
        }
      }
    val pathList = prunedPaths
      .map(PathFeasibility.keepConnected)
      .flatMap(BranchTrimming.trim)
      .map(path => GuardOptionality(path, taintControlFlowProvenance))
      .map { path =>
        val cleaned = path.copy(path = path.path.filterNot(isDeclaration))
        if (cleaned.path.exists(node => UnresolvedCallRegistry.contains(node.id()))) cleaned.copy(unresolved = true)
        else cleaned
      }
      .filter(path => path.path.nonEmpty)
      .toList
    val slices = TaintSliceBuilder.build(pathList, taintSourceNodes, Some(new SqlProbeSelector))
    val flows  = CompactFlowBuilder.build(pathList, taintSourceNodes)
    val graphs = SinkGraphBuilder.build(pathList, taintSourceNodes)
    TaintAnalysisResult(pathList.iterator, context.newDataflowEdges, slices, flows, graphs)
  }

  /** True when `from` can reach `to` through CFG successors inside the same method. Nodes in other methods (method
    * parameters and returns of the interprocedural path) are kept as is.
    */
  private def cfgReaches(from: CfgNode, to: CfgNode): Boolean = {
    if (from.id() == to.id()) return true
    if (Option(from.method).exists(_.id() != to.method.id())) return true
    val visited = scala.collection.mutable.Set.empty[Long]
    val queue   = scala.collection.mutable.Queue.empty[CfgNode]
    queue.enqueue(from)
    var budget = 4000
    while (queue.nonEmpty && budget > 0) {
      budget -= 1
      val node = queue.dequeue()
      if (visited.add(node.id())) {
        if (node.id() == to.id()) return true
        node.cfgNext.foreach(queue.enqueue)
      }
    }
    false
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
    * The reconstructed path goes through the guard. In control-structure mode the default path filter is bypassed (see
    * [[analyze]]), so the traced path is kept as is; otherwise it still has to pass the sanitizer checks, and when it
    * does not the sink is kept as a single-node path so that no sink is lost.
    *
    * @see
    *   [[untaintedSinkPaths]]
    */
  private def emptySinkPath(kind: String, sink: CfgNode, taintedPaths: List[TaintPath]): TaintPath = {
    val singleNodePath = TaintPath(kind, true, List(sink), Some(sink))
    val tracedPath = emptySinkTracer
      .trace(sink, taintedPaths)
      .map(nodes => taintControlFlowProvenance.enhance(TaintPath(kind, true, nodes, Some(sink))))
    if (enableControlStructure) tracedPath.getOrElse(singleNodePath)
    else tracedPath.filter(pathFilter.isValid).getOrElse(singleNodePath)
  }

  /** refactor a path by appending the real sink node if it exists in given map
    */
  private def refactorPath(path: Path, argumentToCall: Map[CfgNode, CfgNode]): Path = {
    argumentToCall.get(path.elements.last.asInstanceOf[CfgNode]) match {
      case Some(realSink) => Path(path.elements :+ realSink)
      case None           => path
    }
  }

  /** Declarations are not executable statements: they must never enter a dataflow path, nor be extended or traced. */
  private def isDeclaration(node: CfgNode): Boolean =
    node.isInstanceOf[Method] || node.isInstanceOf[TypeDecl] || node.isInstanceOf[Member]

  private def extractCfgNodes(path: Path): List[CfgNode] =
    path.elements.collect { case node: CfgNode if !isDeclaration(node) => node }
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
    enableImplicitTaint: Boolean = false,
    includeUntaintedSinks: Boolean = true
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
      enableImplicitTaint,
      includeUntaintedSinks
    )
  }
}
