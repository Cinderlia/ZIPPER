package bee.zipper.core.analysis.dataflow.reachingdef

import bee.zipper.core.analysis.dataflow.iteration.InterDataflowAnalysis
import bee.zipper.core.analysis.dataflow.iteration.fact.DataflowResult
import bee.zipper.core.analysis.graph.icfg.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

/** A set of definition nodes, represented as a bit set indexed by `XReachingDef#rankToNode`.
  *
  * `java.util.BitSet` is used instead of `scala.collection.mutable.BitSet` on purpose: the equality of a Scala sorted
  * set is element-wise (it iterates both sets and compares every element through an `Ordering`), which turns the
  * fixpoint comparison of two large facts into millions of boxed comparisons. The JDK implementation compares the
  * backing words and supports word-level union/difference, which is orders of magnitude cheaper on facts holding
  * thousands of bits.
  */
type ReachingDefFact = java.util.BitSet

object XReachingDef {

  /** Immutable empty fact, shared as the default value of the `gen`/`kill` maps. It is never mutated. */
  private[reachingdef] val EmptyFact: ReachingDefFact = new ReachingDefFact

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
      val size = fact.cardinality()
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
    // Only statements that actually define a variable can become a member of a reaching-def fact, so the rank space
    // is restricted to them. Using every sparse node as a potential bit index would keep each BitSet as wide as the
    // whole program and make the fixed point run out of time and memory on large code bases.
    (sorted ++ unvisited).filter(node => utils.getDefVarsOf(node).nonEmpty).toArray
  }
  private val nodeToRank: Map[CfgNode, Int] = rankToNode.iterator.zipWithIndex.toMap
  private val debug                         = java.lang.Boolean.getBoolean("zipper.reachingdef.debug")
  if (debug) {
    println(s"[reachingdef] definition nodes=${rankToNode.length} of ${icfg.getNodes.size}")
  }

  // generate the 'gen' and 'kill' set in advance
  private type ReachingDefMap = Map[CfgNode, ReachingDefFact]
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
    if (debug) {
      println(s"[reachingdef] sparse icfg nodes=$nodeSize edges=${icfg.getEdges.size}")
      val selfLoopNodes = icfg.getNodes.count(n => icfg.getInEdgesOf(n).exists(_.from == n))
      println(s"[reachingdef] self-loop nodes=$selfLoopNodes")
    }
  }

  private def factOfRank(rank: Int): ReachingDefFact = {
    val fact = new ReachingDefFact
    fact.set(rank)
    fact
  }

  // initialize the 'gen' set for each node in ICFG, representing generated definitions
  private def initGen(): ReachingDefMap = {
    icfg.getNodes
      .map(node =>
        val defVars = utils.getDefVarsOf(node)
        val gen =
          if (defVars.isEmpty) XReachingDef.EmptyFact // indicate this node is not a definition statement
          else factOfRank(nodeToRank(node))
        node -> gen
      )
      .toMap
      .withDefaultValue(XReachingDef.EmptyFact)
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

    if (debug) {
      val defCounts = mutable.Map.empty[V, Int].withDefaultValue(0)
      icfg.getNodes.foreach(node => utils.getDefVarsOf(node).foreach(v => defCounts(v) += 1))
      val top       = defCounts.toSeq.sortBy(-_._2).take(5).map { case (v, c) => s"$v -> $c" }.mkString(", ")
      val totalDefs = defCounts.values.sum
      println(
        s"[reachingdef] variables=${defCounts.size} definitionPairs=$totalDefs maxDefsPerVariable=${defCounts.values.maxOption
            .getOrElse(0)} top=$top"
      )
    }

    def killsOf(node: CfgNode): ReachingDefFact = {
      val genFact = gen(node)
      if (genFact.isEmpty) {
        XReachingDef.EmptyFact
      } else {
        val kill = new ReachingDefFact
        var g    = genFact.nextSetBit(0)
        while (g >= 0) {
          definitionsOfSameVariable(rankToNode(g)).foreach(kill.set)
          g = genFact.nextSetBit(g + 1)
        }
        kill
      }
    }

    icfg.getNodes
      .map(node => node -> killsOf(node))
      .toMap
      .withDefaultValue(XReachingDef.EmptyFact)
  }

  override def isForward: Boolean = true

  override def newBoundaryFact: ReachingDefFact = new ReachingDefFact

  override def newInitialFact: ReachingDefFact = new ReachingDefFact

  override def meetInto(fact: ReachingDefFact, target: ReachingDefFact): Unit = {
    target.or(fact)
  }

  override def transferEdge(edge: ICfgEdge, fact: ReachingDefFact): ReachingDefFact = fact

  private val transferCalls   = new java.util.concurrent.atomic.AtomicLong()
  private val transferChanges = new java.util.concurrent.atomic.AtomicLong()
  private val transferStartMs = System.currentTimeMillis()

  override def transferNode(node: CfgNode, in: ReachingDefFact, out: ReachingDefFact): Boolean = {
    // `in` and `out` can be the very same object: initializeForward aliases the in-fact of a node with a single
    // incoming edge to the out-fact of its predecessor, so a node sitting on a self loop ends up with in eq out.
    // Clearing `out` before reading `in` would then discard the incoming fact, the node would never reach a fixed
    // point and the solver would keep re-queuing its successors forever. Compute the new fact first, then update
    // the out-fact in place only when it actually changed.
    val genFact  = gen(node)
    val killFact = kill(node)
    val changed =
      if (genFact.isEmpty && killFact.isEmpty) {
        // Most statements do not define anything: the out-fact is simply a copy of the in-fact. Compare directly to
        // avoid allocating a full copy on every visit.
        val c = !out.equals(in)
        if (c) {
          out.clear()
          out.or(in)
        }
        c
      } else {
        val newOut = in.clone().asInstanceOf[ReachingDefFact]
        newOut.andNot(killFact)
        newOut.or(genFact)
        val c = !out.equals(newOut)
        if (c) {
          out.clear()
          out.or(newOut)
        }
        c
      }
    if (debug) {
      val calls = transferCalls.incrementAndGet()
      if (changed) transferChanges.incrementAndGet()
      if (calls % 200000 == 0) {
        val elapsed = System.currentTimeMillis() - transferStartMs
        println(s"[reachingdef] transferNode calls=$calls changed=${transferChanges.get} elapsedMs=$elapsed")
      }
    }
    changed
  }
}
