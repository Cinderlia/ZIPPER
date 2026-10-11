package bee.zipper.core.semantic

import io.joern.dataflowengineoss.semanticsloader.{FlowSemantic, FullNameSemantics, PassThroughMapping}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

class ZipperSemantics(methodToSemantic: Map[String, FlowSemantic]) extends FullNameSemantics(methodToSemantic) {

  /** user-defined methods in project */
  private val definedMethods = mutable.Set.empty[String]

  /** indicate whether it is in DDG construction stage */
  private var isDdgBuildingStage: Boolean = true

  /** Initialize all the method semantics that use regex with all their regex results before query time.
    */
  override def initialize(cpg: Cpg): Unit = {
    super.initialize(cpg)
    definedMethods.clear()
    definedMethods ++= cpg.method.isExternal(false).map(_.name)
  }

  def ddgBuildingStage(enable: Boolean): Unit = isDdgBuildingStage = enable

  private val PTF =
    FlowSemantic("").copy(mappings = FlowSemantic.from("", List((0, 0), (0, -1))).mappings :+ PassThroughMapping)
  private val stopFlow = FlowSemantic.from("", List((1, 1), (2, 2), (3, 3), (4, 4), (5, 5), (6, 6)))

  override def forMethod(method: Method): Option[FlowSemantic] = {
    val opt = super.forMethod(method)
    if (isDdgBuildingStage) opt
    else {
      opt.orElse {
        // user-defined function
        if (!method.isExternal) None
        // unresolved call && no same name function defined
        else if (method.isExternal && !definedMethods.contains(method.name)) Some(PTF)
        // unresolved call && exist same name function defined
        else Some(stopFlow)
      }
    }
  }
}
