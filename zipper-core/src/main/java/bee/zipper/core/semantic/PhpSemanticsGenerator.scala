package bee.zipper.core.semantic

import bee.zipper.core.semantic.SemanticUtil.*
import bee.zipper.core.vuln.{SanitizerManager, SourceSinkSpecManager}
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.semanticsloader.*
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.Languages

object PhpSemanticsGenerator extends SemanticsGenerator {
  private val builtinNames                = PhpBuiltins.FuncNames ++ Set(PhpOperators.concatOp, PhpOperators.encaps)
  private val typeSanitizerNames          = SanitizerManager.getSanitizer(Languages.PHP).typeSanitizer
  private val genericStringSanitizerNames = SanitizerManager.getSanitizer(Languages.PHP).genericSanitizer
  private val sinkNames =
    SourceSinkSpecManager
      .getSink(Languages.PHP)
      .flatMap(x => x._2.methods.map(_.methodName) ++ x._2.functions.map(_.name))
      .toSet

  private val basicFlowSemantics: List[FlowSemantic] = {
    val assignmentNames = Set(PhpOperators.assignmentConcatOp)
    val assignments     = List(FlowSemantic.from(PhpOperators.assignmentConcatOp, List((2, 1), (1, 1), (2, -1))))
    val builtins =
      builtinNames
        .diff(assignmentNames ++ typeSanitizerNames ++ genericStringSanitizerNames ++ sinkNames)
        .map(name => PTF(name))
    assignments ++ builtins
  }

  private val (exploitModeSemantic, nonExploitModeSemantic) = {
    val typeSanitizerFlowSemantics = typeSanitizerNames.map(stopFlow)
    val sinkFlowSemantics          = sinkNames.map(x => PTF(x))
    val exploitModel = ZipperSemantics(
      FullNameSemantics
        .fromList(
          DefaultSemantics().elements
            ++ typeSanitizerFlowSemantics
            ++ genericStringSanitizerNames.map(x => PTF(x))
            ++ sinkFlowSemantics
            ++ basicFlowSemantics
        )
        .methodToSemantic
    )
    val nonExploitModel = ZipperSemantics(
      FullNameSemantics
        .fromList(
          DefaultSemantics().elements
            ++ typeSanitizerFlowSemantics
            ++ genericStringSanitizerNames.map(x => stopFlow(x))
            ++ sinkFlowSemantics
            ++ basicFlowSemantics
        )
        .methodToSemantic
    )
    (exploitModel, nonExploitModel)
  }

  override val genericSemantic: ZipperSemantics = {
    val remainingFlowSemantics = (typeSanitizerNames ++ genericStringSanitizerNames ++ sinkNames).map(x => PTF(x))
    ZipperSemantics(
      FullNameSemantics
        .fromList(
          DefaultSemantics().elements
            ++ remainingFlowSemantics
            ++ basicFlowSemantics
        )
        .methodToSemantic
    )
  }

  override def taintSemantic(exploitMode: Boolean = true): ZipperSemantics =
    if (exploitMode) exploitModeSemantic else nonExploitModeSemantic
}
