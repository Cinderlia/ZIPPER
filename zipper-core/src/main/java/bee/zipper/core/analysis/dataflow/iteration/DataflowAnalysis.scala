package bee.zipper.core.analysis.dataflow.iteration

import bee.zipper.core.analysis.Analysis
import bee.zipper.core.analysis.dataflow.iteration.fact.DataflowResult
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

trait DataflowAnalysis[Fact] extends Analysis[DataflowResult[Fact]] {
  def cfg: Method

  /** max iterations of analysis
    */
  def iterations: Int

  override def analyze(): DataflowResult[Fact] = {
    val result = new DataflowResult[Fact]
    initializeForward(result)
    doSolveForward(result)
    result
  }

  protected def newBoundaryFact: Fact

  protected def newInitialFact: Fact

  protected def meetInto(fact: Fact, target: Fact): Unit

  protected def transferNode(node: CfgNode, in: Fact, out: Fact): Boolean

  private final def initializeForward(result: DataflowResult[Fact]): Unit = {
    val cfgEntry = cfg.cfgFirst.head
    result.setInFact(cfgEntry, newBoundaryFact)
    result.setOutFact(cfgEntry, newBoundaryFact)
    for (node <- cfg.cfgNode) {
      if (node != cfgEntry) {
        result.setInFact(node, newInitialFact)
        result.setOutFact(node, newInitialFact)
      }
    }
  }

  private final def doSolveForward(result: DataflowResult[Fact]): Unit = {
    def line(node: CfgNode): Int = node.lineNumber.getOrElse(0)

    val worklist = mutable.PriorityQueue.empty[CfgNode](Ordering.fromLessThan[CfgNode](line(_) > line(_)))
    cfg.cfgNode.foreach(worklist += _)

    var iterationCount = 0
    while (worklist.nonEmpty && iterationCount < iterations) {
      val iterationSize = worklist.size
      for (i <- 0 until iterationSize) {
        val node = worklist.dequeue()
        val in   = result.getInFact(node)
        // merge out fact from all precursor nodes
        node.cfgPrev.foreach(pred => meetInto(result.getOutFact(pred), in))
        val out     = result.getOutFact(node)
        val changed = transferNode(node, in, out)
        if (changed)
          node.cfgNext.foreach(succ => worklist += succ)
      }
      iterationCount += 1
    }
  }
}
