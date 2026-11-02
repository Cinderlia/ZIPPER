package bee.zipper.core.analysis.dataflow.reachingdef

import bee.zipper.core.analysis.dataflow.iteration.InterDataflowAnalysis
import bee.zipper.core.analysis.dataflow.iteration.fact.DataflowResult
import bee.zipper.core.analysis.graph.icfg.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

type ReachingDefFact = mutable.BitSet

object XReachingDef {

  private def debugStats(
    icfg: DefaultICfg,
    rankToNode: Array[CfgNode],
    dataflowResult: DataflowResult[ReachingDefFact]
  ): Unit = {
    val facts    = dataflowResult.getInFacts
    var total    = 0L
    var max      = 0
    var nonEmpty = 0
    facts.foreach { case (_, fact) =>
      val size = fact.size
      total += size
      if (size > max) max = size
      if (size > 0) nonEmpty += 1
    }
    val runtime = Runtime.getRuntime
    val usedMB  = (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024
    println(
      s"[reachingdef] icfgNodes=${icfg.getNodes.size} bitsetWidth=${rankToNode.length} facts=${facts.size} " +
        s"nonEmpty=$nonEmpty totalBits=$total maxBits=$max usedMB=$usedMB"
    )
  }
}

class XReachingDef[V](val icfg: DefaultICfg, val utils: XUtils[V], val iterations: Option[Int])
    extends InterDataflowAnalysis[ReachingDefFact] {
  // prune the ICFG for sparse analysis
  pruneICfg()

  /** Compact rank of every sparse node. The rank is used as the bit index of a definition: using the ICFG order
    * directly would make every bit set as wide as the whole ICFG and exhaust the heap on large programs. Nodes that are
    * not reachable from any sink (i.e. that still sit on a residual cycle) are appended so that they get a valid rank.
    */
  val rankToNode: Array[CfgNode] = {
    val sorted    = icfg.getSortedNodes
    val sortedSet = sorted.toSet
    val unvisited = icfg.getNodes.filterNot(sortedSet.contains).toList
    (sorted ++ unvisited).toArray
  }
  private val nodeToRank: Map[CfgNode, Int] = rankToNode.iterator.zipWithIndex.toMap

  // generate the 'gen' and 'kill' set in advance
  private type ReachingDefMap = Map[CfgNode, mutable.BitSet]
  private val gen: ReachingDefMap  = initGen()
  private val kill: ReachingDefMap = initKill(gen)

  /** Convert the fixed point of the analysis into the def-use representation without materializing one list of
    * `CfgNode` per statement.
    */
  def toReachingDefResult(dataflowResult: DataflowResult[ReachingDefFact]): ReachingDefResult = {
    if (java.lang.Boolean.getBoolean("zipper.reachingdef.debug")) {
      XReachingDef.debugStats(icfg, rankToNode, dataflowResult)
    }
    ReachingDefResult.fromBits(dataflowResult.getInFacts.toMap, rankToNode)
  }

  // build the sparse graph
  private def pruneICfg(): Unit = {
    val sparseTransformer = new DefaultICfgSparseTransformer(icfg, utils.isRelatedStmt)
    sparseTransformer.transform()
    icfg.sort()
    val sortedSize = icfg.getSortedNodes.size
    val nodeSize   = icfg.getNodes.size
    if (sortedSize < nodeSize) {
      println(
        s"[reachingdef] warning: ${nodeSize - sortedSize} of $nodeSize sparse nodes are not sink-reachable, " +
          "which indicates a residual cycle in the sparse ICFG"
      )
    }
    if (java.lang.Boolean.getBoolean("zipper.reachingdef.debug")) {
      println(s"[reachingdef] sparse icfg nodes=$nodeSize edges=${icfg.getEdges.size}")
    }
  }

  // initialize the 'gen' set for each node in ICFG, representing generated definitions
  private def initGen(): ReachingDefMap = {
    icfg.getNodes
      .map(node =>
        val defVars = utils.getDefVarsOf(node)
        val gen =
          if (defVars.isEmpty) mutable.BitSet.empty // indicate this node is not a definition statement
          else mutable.BitSet(nodeToRank(node))
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

    def definitionsOfSameVariable(definition: CfgNode): List[Int] =
      utils
        .getDefVarsOf(definition)
        .flatMap(variableToDefinitions.get)
        .map(nodeToRank)
        .toList

    def killsOf(node: CfgNode): mutable.BitSet = {
      val kill = mutable.BitSet.empty
      gen(node).foreach(g => kill ++= definitionsOfSameVariable(rankToNode(g)))
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
