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
    initialNodes.foreach(worklist += _)

    var iterationCount = 0
    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      val iterationSize = worklist.size
      for (i <- 0 until iterationSize) {
        val node     = worklist.dequeue()
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
          inEdges.foreach(inEdge =>
            var fact = result.getOutFact(inEdge.from)
            if (needTransferEdge(inEdge)) {
              fact = transferEdge(inEdge, fact)
            }
            meetInto(fact, in)
          )
        }
        val out     = result.getOutFact(node)
        val changed = transferNode(node, in, out)
        if (changed)
          icfg.getSuccsOf(node).foreach(succ => worklist += succ)
      }
      iterationCount += 1
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
