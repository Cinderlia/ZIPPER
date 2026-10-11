// ZIPPER Modified [Begin] - new file to more strictly validate edges in dataflow graph
package io.joern.dataflowengineoss.queryengine

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

object StrictEdgeValidator {
  // In non-strict mode, the $arr variable in below code will be tainted
  //   $arr = ["a" => $_GET["a"]];
  //   echo $arr; // alert
  def isValidEdge(from: CfgNode, to: CfgNode): Boolean = !isContainer(from, to)

  // === copy from [[DdgGenerator]] ===
  private val containerSet =
    Set(Operators.fieldAccess, Operators.indexAccess, Operators.indirectIndexAccess, Operators.indirectFieldAccess)

  /** Determine whether the node `to` is a container for `from`, e.g., to = `ptr` while from = `ptr->foo`.
    */
  private def isContainer(from: CfgNode, to: CfgNode): Boolean = {
    from match {
      case call: Call if containerSet.contains(call.name) =>
        call.argument.headOption.exists { base =>
          nodeToString(to) == nodeToString(base)
        }
      case _ => false
    }
  }

  private def nodeToString(node: StoredNode): Option[String] = {
    node match {
      case ident: Identifier     => Some(ident.name)
      case exp: Expression       => Some(exp.code)
      case p: MethodParameterIn  => Some(p.name)
      case p: MethodParameterOut => Some(p.name)
      case _                     => None
    }
  }
}
// ZIPPER Modified [End]
