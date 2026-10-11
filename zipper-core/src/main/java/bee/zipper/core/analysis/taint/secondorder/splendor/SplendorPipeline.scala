package bee.zipper.core.analysis.taint.secondorder.splendor

import bee.zipper.core.Api
import bee.zipper.core.analysis.graph.vfg.Vfg
import bee.zipper.core.analysis.model.database.DatabaseSchema
import bee.zipper.core.analysis.taint.secondorder.TwoPhaseTaintAnalysis
import bee.zipper.core.analysis.taint.sourcesink.{TaintSinkSearcher, TaintSourceSearcher, TaintSink}
import bee.zipper.core.analysis.taint.{TaintAnalysis, TaintAnalysisResult}
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

class SplendorPipeline(
  cpg: Cpg,
  sources: List[CfgNode],
  kindToSinks: Map[String, List[TaintSink]],
  schema: DatabaseSchema,
  extraAnchors: List[String] = List.empty,
  vsa: ValueSetResult,
  exploitMode: Boolean = false,
  enableReachAnalysis: Boolean = false
)(implicit ctx: Api)
    extends TaintAnalysis {
  override def analyze(): TaintAnalysisResult = {
    // step1. detect database operation anchors by frequency analysis
    val anchors = {
      val sinks    = kindToSinks.flatMap(_._2).toList
      val detector = new AnchorDetector(cpg, sources, sinks)
      detector.detect() ++ extraAnchors
    }
    // step2. recognize the database-operation triples by fuzzy matching
    val triples = {
      val recognizer = new TripleRecognizer(cpg, anchors, schema)
      recognizer.recognize()
    }
    // step3. two phase taint analysis
    val taintAnalysis =
      new TwoPhaseTaintAnalysis(cpg, triples, sources, kindToSinks, vsa, exploitMode, enableReachAnalysis)
    taintAnalysis.analyze()
  }
}

object SplendorPipeline {
  def apply(
    cpg: Cpg,
    vfg: Vfg,
    schema: DatabaseSchema,
    extraAnchors: List[String] = List.empty,
    vsa: ValueSetResult,
    exploitMode: Boolean = false,
    enableReachAnalysis: Boolean = false
  )(implicit ctx: Api): SplendorPipeline = {
    val sources = {
      val searcher = TaintSourceSearcher.create(cpg, vfg)
      searcher.search()._1
    }
    val sinks = {
      val searcher = TaintSinkSearcher.create(cpg, vsa)
      searcher.search()
    }
    new SplendorPipeline(cpg, sources, sinks, schema, extraAnchors, vsa, exploitMode, enableReachAnalysis)
  }
}
