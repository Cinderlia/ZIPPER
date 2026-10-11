package bee.zipper.core.analysis.taint

import bee.zipper.core.analysis.AnalysisResult
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import java.util

/** @param paths
  *   taint paths
  * @param newDataflowEdges
  *   new dataflow edges introduced by on-demand alias analysis. Note the taint analysis is lazy, we should access it
  *   after taint analysis finished
  */
case class TaintAnalysisResult(
  paths: Iterator[TaintPath],
  newDataflowEdges: util.List[(CfgNode, CfgNode)] = new util.ArrayList[(CfgNode, CfgNode)]
) extends AnalysisResult
