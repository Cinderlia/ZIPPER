package bee.zipper.core.analysis.defuse

import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XUtils}
import bee.zipper.core.analysis.graph.icfg.ICfg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

trait XDefUse[V] {
  val icfg: ICfg

  val reachingDefResult: ReachingDefResult

  val utils: XUtils[V]

  // key is the stmt and the Var used by the stmt. value is the reachDef stmt of the Var
  val defines: mutable.MultiDict[(CfgNode, V), CfgNode] = mutable.MultiDict.empty[(CfgNode, V), CfgNode]
  // key is reachDef stmt. value is the stmt that use the Var defined by key
  val uses: mutable.MultiDict[CfgNode, CfgNode] = mutable.MultiDict.empty[CfgNode, CfgNode]
  // key is defStmt and the defined Var of it
  val useToVar: mutable.MultiDict[(CfgNode, CfgNode), V] = mutable.MultiDict.empty[(CfgNode, CfgNode), V]

  def getUsesOf(defStmt: CfgNode): List[CfgNode] = uses.get(defStmt).toList

  /** Get the vars defined by `defStmt` and used by `useStmt`
    */
  def getUseVarsOf(defStmt: CfgNode, useStmt: CfgNode): List[V] = useToVar.get((defStmt, useStmt)).toList

  def getDefinesOf(stmt: CfgNode, useVar: V): List[CfgNode] = defines.get((stmt, useVar)).toList

  def getReachingDefsOf(ctx: CfgNode, v: V): Set[Call] = {
    val all  = reachingDefResult.getReachingDefs(ctx).toSet
    val defs = utils.getDefStmtsOf(v).intersect(all)
    defs.collect { case x: Call => x }
  }

  /** The source part of reaching definitions, e.g. the X of `x = X`
    */
  def getReachingDefSourcesOf(ctx: CfgNode, v: V): Set[CfgNode] = {
    getReachingDefsOf(ctx, v).flatMap(_.argumentOption(2))
  }
}
