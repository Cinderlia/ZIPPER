package bee.zipper.core.analysis.dataflow.reachingdef

import bee.zipper.core.analysis.dataflow.iteration.InterDataflowAnalysis
import bee.zipper.core.analysis.dataflow.iteration.fact.DataflowResult
import bee.zipper.core.analysis.graph.icfg.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

type ReachingDefFact = mutable.BitSet

object XReachingDef {
  def toReachingDefResult(icfg: DefaultICfg, dataflowResult: DataflowResult[ReachingDefFact]): ReachingDefResult = {
    val map =
      dataflowResult.getInFacts.map { case (stmt, reachingDefs) =>
        stmt -> reachingDefs.toList.flatMap(icfg.node)
      }.toMap
    ReachingDefResult(map)
  }
}

class XReachingDef[V](val icfg: DefaultICfg, val utils: XUtils[V], val iterations: Option[Int])
    extends InterDataflowAnalysis[ReachingDefFact] {
  // prune the ICFG for sparse analysis
  pruneICfg()
  // generate the 'gen' and 'kill' set in advance
  private type ReachingDefMap = Map[CfgNode, mutable.BitSet]
  private val gen: ReachingDefMap  = initGen()
  private val kill: ReachingDefMap = initKill(gen)

  // build the sparse graph
  private def pruneICfg(): Unit = {
    val sparseTransformer = new DefaultICfgSparseTransformer(icfg, utils.isRelatedStmt)
    sparseTransformer.transform()
    icfg.sort()
  }

  // initialize the 'gen' set for each node in ICFG, representing generated definitions
  private def initGen(): ReachingDefMap = {
    icfg.getNodes
      .map(node =>
        val defVars = utils.getDefVarsOf(node)
        val gen =
          if (defVars.isEmpty) mutable.BitSet.empty // indicate this node is not a definition statement
          else mutable.BitSet(icfg.order(node))
        node -> gen
      )
      .toMap
      .withDefaultValue(mutable.BitSet.empty)
  }

  // initialize the 'kill' set for each node in ICFG, representing definitions killed by given node
  private def initKill(gen: ReachingDefMap): ReachingDefMap = {
    // map each variable to the statement where it is defined
    val variableToDefinitions = {
      val map = mutable.MultiDict.empty[V, CfgNode]
      icfg.getNodes.foreach(node =>
        val defVars = utils.getDefVarsOf(node)
        defVars.foreach(defVar => map += defVar -> node)
      )
      map
    }

    def definitionsOfSameVariable(definition: Int): List[Int] = {
      icfg
        .node(definition)
        .map(definition =>
          utils
            .getDefVarsOf(definition)
            .flatMap(variableToDefinitions.get)
            .map(icfg.order)
            .toList
        )
        .getOrElse(List.empty)
    }

    def killsOf(node: CfgNode): mutable.BitSet = {
      val kill = mutable.BitSet.empty
      gen(node).foreach(g => kill ++= definitionsOfSameVariable(g))
      kill
    }

    icfg.getNodes
      .map(node => node -> killsOf(node))
      .toMap
      .withDefaultValue(mutable.BitSet.empty)
  }

  override def isForward: Boolean = true

  override def newBoundaryFact: ReachingDefFact = new ReachingDefFact

  override def newInitialFact: ReachingDefFact = new ReachingDefFact

  override def meetInto(fact: ReachingDefFact, target: ReachingDefFact): Unit = {
    target ++= fact
  }

  override def transferEdge(edge: ICfgEdge, fact: ReachingDefFact): ReachingDefFact = fact

  override def transferNode(node: CfgNode, in: ReachingDefFact, out: ReachingDefFact): Boolean = {
    val oldOut = out.clone()
    out.clear()
    out ++= gen(node).union(in.diff(kill(node)))
    oldOut != out
  }
}
