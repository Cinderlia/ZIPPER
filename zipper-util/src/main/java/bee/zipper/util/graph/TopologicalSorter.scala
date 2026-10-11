package bee.zipper.util.graph

import scala.collection.mutable
import scala.util.control.Breaks.*

class TopologicalSorter[N, E <: Edge[N]](graph: Graph[N, E]) {
  private val sortedList  = mutable.ListBuffer.empty[N]
  private val nodeToOrder = mutable.Map.empty[N, Int]
  private val orderToNode = mutable.Map.empty[Int, N]
  private val visited     = mutable.Set.empty[N]

  def sort(): Unit = {
    sortedList.clear()
    nodeToOrder.clear()
    orderToNode.clear()
    graph.getNodes.filter(node => graph.getOutEdgesOf(node).isEmpty).foreach(visit)
    visited.clear() // release memory
  }

  def isSorted: Boolean = sortedList.nonEmpty

  def order(node: N): Int = nodeToOrder.getOrElse(node, 0)

  def node(order: Int): Option[N] = orderToNode.get(order)

  def getSortedList: mutable.ListBuffer[N] = sortedList

  /** Uses stack to simulate DFS (copy from Tai-e)
    */
  private def visit(node: N): Unit = {
    if (visited.contains(node)) return
    val stack = mutable.Stack.empty[N]
    stack.push(node)
    while (stack.nonEmpty) {
      val curr = stack.top
      visited.add(curr)
      var hasUnvisitedPred = false
      breakable {
        for (pred <- graph.getPredsOf(curr)) {
          if (!visited.contains(pred)) {
            stack.push(pred)
            hasUnvisitedPred = true
            break
          }
        }
      }
      if (!hasUnvisitedPred) {
        sortedList += curr
        nodeToOrder += curr            -> sortedList.size
        orderToNode += sortedList.size -> curr
        stack.pop()
      }
    }
  }
}
