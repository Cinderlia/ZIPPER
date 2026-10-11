package bee.zipper.core.ir

import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.tryAs
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

trait Translator {

  /** convert CPG node to simple IR. When `array(field)Access` appears on the left of an assignment statement, they are
    * converted to `XXXAccess` IR nodes, and are considered `JTempVar` anywhere else. Therefore, the `base` field of all
    * `XXXAccess` is `JVar` (no nested `XXXAccess` occurs)
    */
  def translate(node: CfgNode): Expr = {
    val container     = node.method
    val default: Expr = TmpVar(s"t:${node.id()}", container)

    def forStaticFieldAccess(call: Call): Expr = call.args match {
      case base :: field :: _ => createStaticFieldVar(call, base, field)
      case _                  => default
    }

    def forAssignmentTarget(call: Call): Expr = {
      def isMemoryAccess(name: String): Boolean = {
        name match {
          case Operators.fieldAccess | Operators.indexAccess => true
          case _                                             => false
        }
      }

      def createMemoryAccess(base: Var, key: Var) = call.name match {
        case Operators.fieldAccess => InstanceFieldAccess(base, key)
        case Operators.indexAccess => ArrayAccess(base, key)
      }

      call.name match {
        case name if isMemoryAccess(name) =>
          val opt = for {
            baseOption <- call.argumentOption(1)
            keyOption  <- call.argumentOption(2)
            base       <- translate(baseOption).tryAs[Var]
            key        <- translate(keyOption).tryAs[Var]
          } yield createMemoryAccess(base, key)
          opt.getOrElse(default)
        case _ =>
          default
      }
    }

    node match {
      case call: Call =>
        call.name match {
          case Operators.fieldAccess if isStaticFieldAccess(call) => forStaticFieldAccess(call)
          case _ if call.isAssignmentTarget                       => forAssignmentTarget(call)
          case _                                                  => default
        }

      case id: Identifier           => RealVar(id.name, container)
      case param: MethodParameterIn => RealVar(param.name, container)
      case _                        => default
    }
  }

  protected def createStaticFieldVar(call: Call, base: CfgNode, field: CfgNode): StaticFieldVar

  protected def isStaticFieldAccess(call: Call): Boolean
}

object PHPTranslator extends Translator {
  override protected def createStaticFieldVar(call: Call, base: CfgNode, field: CfgNode): StaticFieldVar = {
    val typeName = base.code match {
      case "$this" | "self" => call.getClosest[TypeDecl].map(_.name).getOrElse("unknown")
      case code             => code
    }
    // the type of [[field]] is FieldIdentifier
    // access static member MyClass::$A => $A
    // access const member MyClass::B => B
    val fieldName = field.code.stripPrefix("$")
    StaticFieldVar(typeName, fieldName)
  }

  override protected def isStaticFieldAccess(call: Call): Boolean = {
    // static member of class
    val isStaticMember = call.code.contains("::")
    // constant fetching (see `astForConstFetchExpr` method in php2joern)
    lazy val isConstantFetch = call.argumentOption(1).exists(_.code == "<global>")
    isStaticMember || isConstantFetch
  }
}
