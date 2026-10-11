package bee.zipper.util.graph

import scala.collection.mutable

trait Graph[N, E <: Edge[N]] {
  protected val sorter = new TopologicalSorter(this)

  final def sort(): Unit = sorter.sort()

  final def isSorted: Boolean = sorter.isSorted

  /** Get the topologically sorted node list. This method must be called after sort()
    */
  final def getSortedNodes: List[N] = sorter.getSortedList.toList

  final def order(node: N): Int = sorter.order(node)

  final def node(order: Int): Option[N] = sorter.node(order)

  def addNode(node: N): Unit

  def addEdge(edge: E): Unit

  def hasNode(node: N): Boolean

  def hasEdge(edge: E): Boolean

  def getEdges: Set[E]

  def getNodes: Set[N]

  def getSuccsOf(node: N): List[N] = getOutEdgesOf(node).map(_.to)

  def getPredsOf(node: N): List[N] = getInEdgesOf(node).map(_.from)

  def getOutEdgesOf(node: N): List[E]

  def getInEdgesOf(node: N): List[E]

  /** Find all reachable paths from `from` node to `to` node
    */
  def find(from: N, to: N): List[List[N]] = find(from, node => node == to)

  def find(from: N, cond: N => Boolean): List[List[N]] = {
    val visited     = mutable.Set.empty[N]
    val queue       = mutable.Queue.empty[List[N]]
    val initialPath = List(from)
    queue.enqueue(initialPath)
    val paths = mutable.ListBuffer.empty[List[N]]
    while (queue.nonEmpty) {
      val path = queue.dequeue()
      val node = path.last
      if (cond(node)) {
        paths += path
      } else {
        visited += node
        val outEdges = getOutEdgesOf(node)
        for (edge <- outEdges) {
          val next = edge.to
          if (!path.contains(next)) {
            queue.enqueue(path :+ next)
          }
        }
      }
    }
    paths.toList
  }

  /** This method finds the shortest path between two nodes in the graph using the Breadth-First Search (BFS) algorithm.
    * BFS is used because it explores all the neighbors at the present depth before moving on to nodes at the next depth
    * level, which makes it suitable for finding the shortest path in a graph.
    *
    * @param from
    *   The starting node of the path.
    * @param to
    *   The ending node of the path.
    * @param maxLength
    *   The maximum length of the path. If the length of the path exceeds this value, the search is stopped. If this
    *   parameter is -1, it means there is no limit on the length of the path.
    * @return
    *   A list of nodes representing the shortest path from `from` to `to`. If no path exists, it returns an empty list.
    *   If the shortest path is longer than `maxLength`, it also returns an empty list.
    */
  def findShortestPath(from: N, to: N, maxLength: Int = -1): List[N] = {
    // Create an empty queue and enqueue the `from` node along with a new path containing only `from`.
    val queue = mutable.Queue.empty[(N, List[N])]
    queue.enqueue((from, List(from)))

    // Loop continues while the queue is not empty.
    while (queue.nonEmpty) {
      // In each iteration, dequeue a node and path.
      val (node, path) = queue.dequeue()

      // Check if the dequeued node is the `to` node. If it is, return the path because BFS guarantees it's the shortest.
      if (node == to) {
        return path
      }

      // If the dequeued node is not the `to` node, iterate over its out edges.
      val outEdges = getOutEdgesOf(node)
      for (edge <- outEdges) {
        // For each out edge, get the `to` node. If this node is not already in the path and the length of the path is less than `maxLength`, create a new path by appending this node to the current path and enqueue it.
        val next = edge.to
        if (!path.contains(next) && (maxLength == -1 || path.length < maxLength)) {
          queue.enqueue((next, path :+ next))
        }
      }
    }

    // If no path exists or the shortest path is longer than `maxLength`, return an empty list.
    List.empty[N]
  }

  /** Find strongly connected components(SCC) using tarjan algorithm. This implementation uses a stack to simulate DFS
    * and is written by GPT4-o
    *
    * @param sort
    *   return SCC in topological sort order if it's true
    */
  def findSCCs(sort: Boolean = false): List[Set[N]] = {
    val nodeToIndex = mutable.Map.empty[N, Int]
    val lowLink     = mutable.Map.empty[N, Int]
    val onStack     = mutable.Set.empty[N]
    val stack       = mutable.Stack.empty[N]
    val sccStack    = mutable.Stack.empty[(N, Iterator[Edge[N]])]
    var index       = 0
    val sccList     = mutable.ListBuffer.empty[Set[N]]

    getNodes.foreach { startNode =>
      if (!nodeToIndex.contains(startNode)) {
        sccStack.push((startNode, getOutEdgesOf(startNode).iterator))

        while (sccStack.nonEmpty) {
          val (node, edges) = sccStack.pop()

          if (!nodeToIndex.contains(node)) {
            nodeToIndex(node) = index
            lowLink(node) = index
            index += 1
            stack.push(node)
            onStack += node
          }

          var continue = true
          while (edges.hasNext && continue) {
            val edge = edges.next()
            if (!nodeToIndex.contains(edge.to)) {
              sccStack.push((node, edges))
              sccStack.push((edge.to, getOutEdgesOf(edge.to).iterator))
              continue = false
            } else if (onStack.contains(edge.to)) {
              lowLink(node) = math.min(lowLink(node), nodeToIndex(edge.to))
            }
          }

          if (continue) {
            if (lowLink(node) == nodeToIndex(node)) {
              val component = mutable.Set.empty[N]
              var found     = false
              while (!found && stack.nonEmpty) {
                val w = stack.pop()
                onStack -= w
                component += w
                found = w == node
              }
              sccList += component.toSet
            }

            if (sccStack.nonEmpty) {
              val (parentNode, parentEdges) = sccStack.top
              lowLink(parentNode) = math.min(lowLink(parentNode), lowLink(node))
            }
          }
        }
      }
    }

    // The SCC generated by tarjan algorithm are returned in reverse order of topological ordering
    if (sort) sccList.reverse.toList
    else sccList.toList
  }

  override def toString: String = {
    val dotDumper = new DotDumper[N, E](this)
    dotDumper.dump()
  }
}
