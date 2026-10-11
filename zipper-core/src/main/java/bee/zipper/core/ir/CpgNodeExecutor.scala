package bee.zipper.core.ir

import bee.zipper.core.AnalysisContext
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

trait CpgNodeExecutor[Ctx] {
  def execute(node: CfgNode, ctx: Ctx)(implicit x: AnalysisContext): Unit = {
    val expr = x.translator.translate(node)
    expr match {
      case v: RealVar                       => executeRealVar(node, v, ctx)
      case staticFieldVar: StaticFieldVar   => executeStaticFieldVar(node.asInstanceOf[Call], staticFieldVar, ctx)
      case fieldAccess: InstanceFieldAccess => executeFieldAccess(node, fieldAccess, ctx)
      case arrayAccess: ArrayAccess         => executeArrayAccess(node, arrayAccess, ctx)
      case tmpVar: TmpVar =>
        val tmpVarName = tmpVar.toString
        node match {
          case literal: Literal =>
            executeLiteral(tmpVarName, literal, ctx)
          case block: Block =>
            /* block's value is determined by the *last node* in this block */
            block.cfgPrev.headOption match {
              case Some(prev) => executeBlock(tmpVarName, prev, ctx)
              case None       =>
            }
          case field: FieldIdentifier => executeFieldIdentifier(tmpVarName, field, ctx)
          case call: Call             => executeCall(tmpVarName, call, ctx)
          case ret: Return            => executeReturn(tmpVarName, ret, ctx)
          case _                      =>
        }
      case _ =>
    }
  }

  protected def executeRealVar(node: CfgNode, v: RealVar, ctx: Ctx): Unit = {}

  protected def executeStaticFieldVar(node: Call, staticFieldVar: StaticFieldVar, ctx: Ctx): Unit = {}

  protected def executeFieldAccess(node: CfgNode, fieldAccess: InstanceFieldAccess, ctx: Ctx): Unit = {}

  protected def executeArrayAccess(node: CfgNode, arrayAccess: ArrayAccess, ctx: Ctx): Unit = {}

  protected def executeLiteral(tmpVarName: String, literal: Literal, ctx: Ctx): Unit = {}

  protected def executeBlock(tmpVarName: String, prev: CfgNode, ctx: Ctx): Unit = {}

  protected def executeFieldIdentifier(tmpVarName: String, id: FieldIdentifier, ctx: Ctx): Unit = {}

  private final def executeCall(tmpVarName: String, call: Call, ctx: Ctx): Unit = {
    val handled =
      executeOperatorCall(tmpVarName, call, ctx) ||
        executeLanguageSpecificFunction(tmpVarName, call, ctx)
    if (!handled)
      executeUnhandledCall(tmpVarName, call, ctx)
  }

  /** @return
    *   true if the call was handled, false otherwise
    */
  protected def executeOperatorCall(tmpVarName: String, call: Call, ctx: Ctx): Boolean

  /** @return
    *   true if the call was handled, false otherwise
    */
  protected def executeLanguageSpecificFunction(tmpVarName: String, call: Call, ctx: Ctx): Boolean

  protected def executeUnhandledCall(tmpVarName: String, call: Call, ctx: Ctx): Unit = {}

  protected def executeReturn(tmpVarName: String, ret: Return, ctx: Ctx): Unit = {}
}
