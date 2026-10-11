package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.cpgcreation.x.TransformPassBase
import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.joern.x2cpg.ValidationMode
import io.joern.x2cpg.utils.NodeBuilders.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes, Operators, PropertyNames}
import io.shiftleft.passes.CpgPass
import io.shiftleft.proto.cpg.Cpg.NodePropertyName
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import org.slf4j.LoggerFactory

class AssignmentRefactorLayer extends LayerCreator {
  override val overlayName: String = "AssignmentRefactorLayer"

  override val description: String = "Refactor the assignmentXXX statements"

  override def create(context: LayerCreatorContext): Unit = {
    val pass = new AssignmentRefactorPass(context.cpg)
    pass.createAndApply()
  }
}

object AssignmentRefactorLayer {
  def run(cpg: Cpg): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new AssignmentRefactorLayer
    layer.run(context)
  }
}

class AssignmentRefactorPass(val cpg: Cpg) extends CpgPass(cpg) with TransformPassBase {
  private val logger                        = LoggerFactory.getLogger(this.getClass)
  private implicit val mode: ValidationMode = ValidationMode.Disabled
  private val operatorMap                   = Map(PhpOperators.assignmentConcatOp -> PhpOperators.concatOp)
  private val symbolMap                     = Map(PhpOperators.assignmentConcatOp -> ".")

  override def run(builder: DiffGraphBuilder): Unit = {
    // val calls = cpg.call.name("<operators?>\\.assignment.+").toList
    val calls = cpg.call.name(PhpOperators.assignmentConcatOp).toList // only handle .+
    calls.foreach(call => {
      val tmpBuilder = Cpg.newDiffGraphBuilder
      try {
        refactor(tmpBuilder, call)
        builder.absorb(tmpBuilder)
      } catch {
        case _: Exception =>
      }
    })
  }

  private def copyIdentifier(id: Identifier, argumentIndex: Int): ExpressionBase = {
    NewIdentifier()
      .name(id.name)
      .typeFullName(id.typeFullName)
      .dynamicTypeHintFullName(id.dynamicTypeHintFullName)
      .lineNumber(id.lineNumber)
      .columnNumber(id.columnNumber)
      .code(id.code)
      .argumentIndex(argumentIndex)
  }

  private def refactor(builder: DiffGraphBuilder, call: Call): Unit = {
    logger.info(s"Refactor assignment ${call.log}")

    val target = call.argument(1)
    val source = call.argument(2)

    target match {
      case id: Identifier =>
        // note the argumentIndex of the copy (as the left side of tmpEvalNode)
        val targetCopy = copyIdentifier(id, argumentIndex = 1)
        // build `targetCopy + source`
        val tmpEvalNode = {
          val operator = evalOperator(call.name)
          val symbol   = symbolMap.getOrElse(call.name, operator.replaceAll("<operators?>\\.", ""))
          val node = newOperatorCallNode(operator, s"${targetCopy.code} $symbol ${source.code}")
            .signature(call.signature)
            .typeFullName(call.typeFullName)
            .lineNumber(call.lineNumber)
            .columnNumber(call.columnNumber)
            .argumentIndex(2) // as the right side of assignment node
          node.setCallArguments(builder, List(targetCopy, source))
          // as the right side of tmpEvalNode
          builder.setNodeProperty(source, PropertyNames.ARGUMENT_INDEX, 2)
          node
        }
        // modify the `assignmentXXX` call node to `assignment`
        call.outE(EdgeTypes.AST).foreach(builder.removeEdge)
        call.outE(EdgeTypes.ARGUMENT).foreach(builder.removeEdge)
        builder.setNodeProperty(call, PropertyNames.NAME, Operators.assignment)
        builder.setNodeProperty(call, PropertyNames.CODE, s"${targetCopy.code} = ${tmpEvalNode.code}")
        call.setCallArguments(builder, List(target, tmpEvalNode))
        // as the left side of assignment node
        builder.setNodeProperty(target, NodePropertyName.ARGUMENT_INDEX.name(), 1)
      case _ =>
    }
  }

  private def evalOperator(name: String): String = {
    operatorMap.get(name) match {
      case Some(x) => x
      case None    => name.replace("assignment", "").replace("operators", "operator").toLowerCase
    }
  }
}
