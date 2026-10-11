package bee.zipper.core.analysis.dataflow.reachingdef

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.collection.parallel.CollectionConverters.*

class UtilsResultHolder[V] {
  val relatedStmts: mutable.Set[CfgNode]           = mutable.Set.empty
  val varToDefStmts: mutable.MultiDict[V, CfgNode] = mutable.MultiDict.empty
  val defStmtToVars: mutable.MultiDict[CfgNode, V] = mutable.MultiDict.empty
  val stmtToUseVars: mutable.MultiDict[CfgNode, V] = mutable.MultiDict.empty

  def union(other: UtilsResultHolder[V]): Unit = {
    relatedStmts ++= other.relatedStmts
    varToDefStmts ++= other.varToDefStmts
    defStmtToVars ++= other.defStmtToVars
    stmtToUseVars ++= other.stmtToUseVars
  }
}

trait XUtils[V](val cpg: Cpg, val holder: UtilsResultHolder[V]) {

  init()

  private def init(): Unit = {
    val holders = cpg.method.toList.par.map(analyze).toList
    holders.foreach(result => holder.union(result))
  }

  protected def analyze(m: Method): UtilsResultHolder[V]

  def getRelatedStmts: mutable.Set[CfgNode] = holder.relatedStmts

  def isRelatedStmt(stmt: CfgNode): Boolean = holder.relatedStmts.contains(stmt)

  def getDefStmtsOf(globVar: V): Set[CfgNode] = holder.varToDefStmts.get(globVar).toSet

  def getDefVarsOf(defStmt: CfgNode): Set[V] = holder.defStmtToVars.get(defStmt).toSet

  def getUsesOf(stmt: CfgNode): Set[V] = holder.stmtToUseVars.get(stmt).toSet
}
