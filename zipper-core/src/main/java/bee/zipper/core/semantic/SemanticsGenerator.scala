package bee.zipper.core.semantic

import io.joern.dataflowengineoss.semanticsloader.*

object SemanticUtil {
  def PTF(name: String, ys: List[(Int, Int)] = List.empty): FlowSemantic =
    FlowSemantic(name).copy(mappings = FlowSemantic.from(name, ys).mappings :+ PassThroughMapping)

  def stopFlow(name: String): FlowSemantic =
    FlowSemantic.from(name, List((1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)))
}

trait SemanticsGenerator {

  /** Semantics for general purpose. It's used to track type-independent data flows.
    */
  def genericSemantic: ZipperSemantics

  /** Semantics for string taint analysis.
    *
    * @param exploitMode
    *   If it is set to true, the semantic will retain the taint paths contains sanitizers
    */
  def taintSemantic(exploitMode: Boolean = true): ZipperSemantics
}

object SemanticsGenerator {
  def genericSemantic(language: String): ZipperSemantics = {
    val semantics = PhpSemanticsGenerator.genericSemantic
    semantics.ddgBuildingStage(true)
    semantics
  }

  def taintSemantic(language: String, exploitMode: Boolean = true): ZipperSemantics = {
    val semantics = PhpSemanticsGenerator.taintSemantic(exploitMode)
    semantics.ddgBuildingStage(false)
    semantics
  }
}
