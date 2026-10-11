package bee.zipper.core.analysis.taint.secondorder.splendor

import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

object DdgUtils {
  type Result = (List[Call], Iterator[(CfgNode, Int)])

  def ddgIn(node: CfgNode, depth: Int, max: Int): Result = {
    node match {
      case parameter: MethodParameterIn =>
        if (depth >= max) (List.empty, Iterator.empty)
        else {
          val callsites = NoResolve.getMethodCallsites(parameter.method).collectAll[Call].toList
          val preds     = parameter.argument(NoResolve).map(arg => (arg, depth + 1))
          (callsites, preds)
        }
      case _ =>
        val preds = node.in(EdgeTypes.REACHING_DEF).collectAll[CfgNode].map(in => (in, depth))
        (List.empty, preds)
    }
  }

  def ddgOut(node: CfgNode, depth: Int, max: Int): Result = {
    val succs             = node.out(EdgeTypes.REACHING_DEF).collectAll[CfgNode]
    lazy val defaultSuccs = succs.map(succ => (succ, depth))
    lazy val default      = (List.empty, defaultSuccs)
    node match {
      case exp: Expression =>
        exp.inCall.headOption match {
          case Some(inCall) =>
            if (succs.nonEmpty && !succs.contains(inCall)) default
            else {
              // node is the argument of user-defined call in this case
              val callees = inCall.callee(NoResolve).isExternal(false).toList
              if (callees.isEmpty) (List(inCall), defaultSuccs)
              else if (depth >= max) (List.empty, Iterator.empty)
              else {
                val succs =
                  callees.parameter.filter(p => p.index == exp.argumentIndex).map(p => (p, depth + 1)).distinct
                (List(inCall), succs)
              }
            }
          case None => default
        }
      case _ => default
    }
  }

}
