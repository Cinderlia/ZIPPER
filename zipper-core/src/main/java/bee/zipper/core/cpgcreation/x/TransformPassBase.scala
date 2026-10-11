package bee.zipper.core.cpgcreation.x

import bee.zipper.util.AnyExtension.*
import flatgraph.DiffGraphBuilder
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.semanticcpg.language.*

trait TransformPassBase {
  extension (expression: ExpressionBase) {
    def setCallArguments(builder: DiffGraphBuilder, args: List[ExpressionBase]): Unit = {
      args.foreach(arg => {
        builder.addEdge(expression, arg, EdgeTypes.ARGUMENT)
        builder.addEdge(expression, arg, EdgeTypes.AST)
      })
    }

    /** create a NewExpressionNode from a existing Node. Note this method will throw exception when encounter
      * unsupported case
      */
    def copy(argumentIndex: Int = -1): (ExpressionBase, DiffGraphBuilder) = {
      val builder = Cpg.newDiffGraphBuilder
      def impl(originNode: ExpressionBase): ExpressionNew = {
        originNode match {
          case id: Identifier =>
            NewIdentifier()
              .name(id.name)
              .typeFullName(id.typeFullName)
              .dynamicTypeHintFullName(id.dynamicTypeHintFullName)
              .lineNumber(id.lineNumber)
              .columnNumber(id.columnNumber)
              .code(id.code)
          case id: FieldIdentifier =>
            NewFieldIdentifier()
              .canonicalName(id.canonicalName)
              .lineNumber(id.lineNumber)
              .columnNumber(id.columnNumber)
              .code(id.code)
          case lit: Literal =>
            NewLiteral()
              .typeFullName(lit.typeFullName)
              .possibleTypes(lit.possibleTypes)
              .code(lit.code)
              .lineNumber(lit.lineNumber)
              .columnNumber(lit.columnNumber)
          case call: Call =>
            val node = NewCall()
              .code(call.code)
              .name(call.name)
              .methodFullName(call.methodFullName)
              .dispatchType(call.dispatchType)
              .signature(call.signature)
              .possibleTypes(call.possibleTypes)
              .dynamicTypeHintFullName(call.dynamicTypeHintFullName)
              .lineNumber(call.lineNumber)
              .columnNumber(call.columnNumber)
            // copy the children of node
            call.outE
              .foreach(edge => {
                val out = impl(edge.dst.as[ExpressionBase])
                builder.addEdge(node, out, edge.label)
              })
            node
          case _ => throw Exception()
        }
      }
      val x = impl(expression)
      argumentIndex match {
        case -1 =>
        case _  => x.argumentIndex = argumentIndex
      }
      (x.as[ExpressionBase], builder)
    }
  }
}
