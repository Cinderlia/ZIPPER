package bee.zipper.core.analysis.taint

import bee.zipper.core.analysis.graph.vfg.Vfg
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

object PHPJoernTaintAnalysis {
  def apply(cpg: Cpg, vfg: Vfg, vsa: ValueSetResult): PHPJoernTaintAnalysis = {
    val sources = {
      val searcher =
        TaintSourceSearcher.create(cpg, vfg, enableWrapperFinder = false, enableIndirectSuperGlobalFetching = false)
      searcher.search()._1
    }
    val sinks = {
      val searcher = TaintSinkSearcher.create(cpg, vsa)
      searcher.search()
    }
    new PHPJoernTaintAnalysis(cpg, sources, sinks)
  }
}

class PHPJoernTaintAnalysis(cpg: Cpg, sources: List[CfgNode], kindToSinks: Map[String, List[TaintSink]])
    extends TaintAnalysis {
  override def analyze(): TaintAnalysisResult = {
    implicit val context: EngineContext = {
      val semantic = DefaultSemantics()
      EngineContext(semantic, EngineConfig(maxArgsToAllow = 3000, strict = false, exploitMode = false))
    }

    val paths = kindToSinks.iterator.flatMap { case (kind, taintSinks) =>
      val (sinks, argumentToCall) = extractSinks(taintSinks)
      sinks
        .reachableByFlows(sources)
        .map(path => refactorPath(path, argumentToCall))
        .map(path => TaintPath(kind, true, extractCfgNodes(path)))
    }
    TaintAnalysisResult(paths)
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
