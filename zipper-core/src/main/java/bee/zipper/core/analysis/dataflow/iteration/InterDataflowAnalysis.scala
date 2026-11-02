package bee.zipper.core.analysis.dataflow.iteration

import bee.zipper.core.analysis.Analysis
import bee.zipper.core.analysis.dataflow.iteration.fact.DataflowResult
import bee.zipper.core.analysis.graph.icfg.{ICfg, ICfgEdge}
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

trait InterDataflowAnalysis[Fact] extends Analysis[DataflowResult[Fact]] {
  protected def icfg: ICfg

  protected def isForward: Boolean

  /** max iterations of analysis. None indicates no iteration limit
    */
  protected def iterations: Option[Int]

  override def analyze(): DataflowResult[Fact] = {
    val result = new DataflowResult[Fact]

    if (isForward) initializeForward(result)
    else initializeBackward(result)

    beforeSolve(result)
    if (isForward) doSolveForward(result)
    else doSolveBackward(result)
    afterSolve(result)

    result
  }

  protected def newBoundaryFact: Fact

  protected def newInitialFact: Fact

  /** Nodes that are initially added to the worklist. The default value is all nodes in ICFG
    */
  protected def initialNodes: Iterable[CfgNode] = icfg.getNodes

  /** Hooks before running solver
    */
  protected def beforeSolve(result: DataflowResult[Fact]): Unit = {}

  /** Hooks after running solver
    */
  protected def afterSolve(result: DataflowResult[Fact]): Unit = {}

  protected def meetInto(fact: Fact, target: Fact): Unit

  protected def transferNode(node: CfgNode, in: Fact, out: Fact): Boolean

  protected def transferEdge(edge: ICfgEdge, fact: Fact): Fact

  protected def needTransferEdge(edge: ICfgEdge): Boolean = false

  protected def initializeForward(result: DataflowResult[Fact]): Unit = {
    def getOutFact(node: CfgNode) = result.getOutFactOrElseUpdate(node, newInitialFact)

    icfg.getNodes.foreach(node =>
      val inEdges = icfg.getInEdgesOf(node)
      if (inEdges.size != 1) result.setInFact(node, newInitialFact)
      else {
        val inEdge = inEdges.head
        if (!needTransferEdge(inEdge)) {
          result.setInFact(node, getOutFact(inEdge.from))
        }
      }
      getOutFact(node)
    )
  }

  protected def doSolveForward(result: DataflowResult[Fact]): Unit = {
    if (!icfg.isSorted) icfg.sort()

    def order(node: CfgNode): Int = icfg.order(node)

    val worklist = mutable.PriorityQueue.empty[CfgNode](Ordering.fromLessThan[CfgNode](order(_) > order(_)))

    // De-duplicate the worklist. A node is reached from every predecessor that changed in a wave, and processing it
    // once per predecessor would re-join all of its incoming facts over and over again; on large programs this makes
    // the cost of high in-degree nodes (such as the sink of the reaching-def analysis) dominate the whole analysis.
    val queued = mutable.HashSet.empty[CfgNode]

    def enqueue(node: CfgNode): Unit = if (queued.add(node)) worklist += node

    initialNodes.foreach(enqueue)

    // Only re-join a predecessor whose out-fact changed since the previous visit of the current node. The facts of a
    // monotone analysis only grow, so an unchanged predecessor cannot contribute anything new.
    val outVersion     = mutable.HashMap.empty[CfgNode, Long]
    val mergedVersions = mutable.HashMap.empty[CfgNode, mutable.HashMap[CfgNode, Long]]
    val debug          = java.lang.Boolean.getBoolean("zipper.reachingdef.debug")

    var iterationCount = 0
    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      val iterationSize = worklist.size
      for (i <- 0 until iterationSize) {
        val node = worklist.dequeue()
        queued -= node
        var in       = result.getInFact(node)
        val inEdges  = icfg.getInEdgesOf(node)
        val inDegree = inEdges.size
        if (inDegree == 1) {
          val inEdge = inEdges.head
          if (needTransferEdge(inEdge)) {
            in = transferEdge(inEdge, result.getOutFact(inEdge.from))
            result.setInFact(node, in)
          }
        } else if (inDegree > 1) {
          val merged = mergedVersions.getOrElseUpdate(node, mutable.HashMap.empty[CfgNode, Long])
          inEdges.foreach { inEdge =>
            val pred = inEdge.from
            if (needTransferEdge(inEdge)) {
              meetInto(transferEdge(inEdge, result.getOutFact(pred)), in)
            } else {
              val version = outVersion.getOrElse(pred, 0L)
              if (!merged.get(pred).contains(version)) {
                meetInto(result.getOutFact(pred), in)
                merged.update(pred, version)
              }
            }
          }
        }
        val out     = result.getOutFact(node)
        val changed = transferNode(node, in, out)
        if (changed) {
          outVersion.update(node, outVersion.getOrElse(node, 0L) + 1L)
          icfg.getSuccsOf(node).foreach(enqueue)
        }
      }
      iterationCount += 1
      if (debug && (iterationCount % 50 == 0 || worklist.isEmpty)) {
        val runtime = Runtime.getRuntime
        val usedMB  = (runtime.totalMemory() - runtime.freeMemory()) / 1024 / 1024
        println(s"[dataflow] iteration=$iterationCount worklist=${worklist.size} usedMB=$usedMB")
      }
    }
  }

  protected def initializeBackward(result: DataflowResult[Fact]): Unit = {
    def getInFact(node: CfgNode) = result.getInFactOrElseUpdate(node, newInitialFact)

    icfg.getNodes.foreach(node =>
      val outEdges = icfg.getOutEdgesOf(node)
      if (outEdges.size != 1) result.setOutFact(node, newInitialFact)
      else {
        val outEdge = outEdges.head
        if (!needTransferEdge(outEdge)) {
          result.setOutFact(node, getInFact(outEdge.to))
        }
      }
      getInFact(node)
    )
  }

  protected def doSolveBackward(result: DataflowResult[Fact]): Unit = {
    if (!icfg.isSorted) icfg.sort()

    def order(node: CfgNode): Int = icfg.order(node)

    val worklist = mutable.PriorityQueue.empty[CfgNode](Ordering.fromLessThan[CfgNode](order(_) < order(_)))
    initialNodes.foreach(worklist += _)

    var iterationCount = 0
    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      val iterationSize = worklist.size
      for (i <- 0 until iterationSize) {
        val node      = worklist.dequeue()
        var out       = result.getOutFact(node)
        val outEdges  = icfg.getOutEdgesOf(node)
        val outDegree = outEdges.size
        if (outDegree == 1) {
          val outEdge = outEdges.head
          if (needTransferEdge(outEdge)) {
            out = transferEdge(outEdge, result.getInFact(outEdge.to))
            result.setOutFact(node, out)
          }
        } else if (outDegree > 1) {
          outEdges.foreach(outEdge =>
            var fact = result.getInFact(outEdge.to)
            if (needTransferEdge(outEdge)) {
              fact = transferEdge(outEdge, fact)
            }
            meetInto(fact, out)
          )
        }
        val in      = result.getInFact(node)
        val changed = transferNode(node, in, out)
        if (changed)
          icfg.getPredsOf(node).foreach(pred => worklist += pred)
      }
      iterationCount += 1
    }
  }
}
