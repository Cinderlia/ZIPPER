package bee.zipper.core.analysis.dataflow.ifds

import bee.zipper.core.analysis.graph.icfg.*
import heros.InterproceduralCFG
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import java.util
import scala.jdk.CollectionConverters.*

class HerosICfg(val icfg: DefaultICfg) extends InterproceduralCFG[CfgNode, Method] {
  def getEntryStmts: util.Collection[CfgNode] =
    icfg.getNodes.filter(node => icfg.getInEdgesOf(node).isEmpty).toList.asJava

  override def getMethodOf(node: CfgNode): Method = node.method

  override def getPredsOf(u: CfgNode): util.List[CfgNode] = icfg.getPredsOf(u).asJava

  override def getSuccsOf(n: CfgNode): util.List[CfgNode] = icfg.getSuccsOf(n).asJava

  override def getCalleesOfCallAt(node: CfgNode): util.Collection[Method] = node match {
    case call: Call => NoResolve.getCalledMethods(call).toList.asJava
    case _          => util.Collections.emptyList()
  }

  override def getCallersOf(m: Method): util.Collection[CfgNode] = NoResolve.getMethodCallsites(m).toList.asJava

  override def getCallsFromWithin(m: Method): util.Set[CfgNode] = m.cfgNode.collectAll[Call].toSet.asJava

  override def getStartPointsOf(method: Method): util.Collection[CfgNode] = method.cfgFirst.toList.asJava

  override def getReturnSitesOfCallAt(callsite: CfgNode): util.Collection[CfgNode] = callsite.cfgNext.toList.asJava

  override def isCallStmt(stmt: CfgNode): Boolean = stmt match {
    case call: Call if !call.name.startsWith("<operator") && !PhpBuiltins.FuncNames.contains(call.name) => true
    case _                                                                                              => false
  }

  override def isExitStmt(stmt: CfgNode): Boolean = stmt.isInstanceOf[MethodReturn]

  override def isStartPoint(stmt: CfgNode): Boolean = stmt.method.cfgFirst.contains(stmt)

  override def allNonCallStartNodes(): util.Set[CfgNode] =
    icfg.getNodes.filter(n => !isCallStmt(n) && !isStartPoint(n)).toSet.asJava

  // TODO
  override def isFallThroughSuccessor(stmt: CfgNode, succ: CfgNode): Boolean = false

  // TODO
  override def isBranchTarget(stmt: CfgNode, succ: CfgNode): Boolean = false
}
