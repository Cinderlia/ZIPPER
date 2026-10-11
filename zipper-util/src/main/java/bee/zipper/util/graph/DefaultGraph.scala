package bee.zipper.util.graph

import scala.collection.mutable

class DefaultGraph[N, E <: Edge[N]] extends Graph[N, E] {
  protected val nodes: mutable.Set[N]             = mutable.Set.empty
  protected val inEdges: mutable.MultiDict[N, E]  = mutable.MultiDict.empty
  protected val outEdges: mutable.MultiDict[N, E] = mutable.MultiDict.empty

  override def addNode(node: N): Unit = nodes += node

  def addNodes(nodesToAdd: Iterable[N]): Unit = nodes ++= nodesToAdd

  override def addEdge(edge: E): Unit = {
    inEdges += edge.to    -> edge
    outEdges += edge.from -> edge
    nodes += edge.to
    nodes += edge.from
  }

  def addEdges(edgesToAdd: Iterable[E]): Unit = edgesToAdd.foreach(addEdge)

  /** Delete given node and edges incident on them.
    */
  def removeNode(node: N): Unit = {
    removeEdges(inEdges.get(node) ++ outEdges.get(node))
    inEdges.removeKey(node)
    outEdges.removeKey(node)
    nodes -= node
  }

  def removeNodes(nodesToRemove: Iterable[N]): Unit = {
    val edgesToRemove = mutable.Set.empty[E]

    nodesToRemove.foreach { node =>
      edgesToRemove ++= inEdges.get(node)
      edgesToRemove ++= outEdges.get(node)
    }

    removeEdges(edgesToRemove)
    nodesToRemove.foreach(node =>
      outEdges.removeKey(node)
      inEdges.removeKey(node)
    )
    nodes --= nodesToRemove
  }

  def removeEdge(edge: E): Unit = {
    inEdges -= edge.to    -> edge
    outEdges -= edge.from -> edge
  }

  def removeEdges(edgesToRemove: Iterable[E]): Unit = {
    edgesToRemove.foreach { edge =>
      inEdges -= edge.to    -> edge
      outEdges -= edge.from -> edge
    }
  }

  override def hasNode(node: N): Boolean = nodes.contains(node)

  override def hasEdge(edge: E): Boolean = getEdges.contains(edge)

  override def getEdges: Set[E] = (inEdges.values ++ outEdges.values).toSet

  override def getNodes: Set[N] = nodes.toSet

  override def getOutEdgesOf(node: N): List[E] = outEdges.get(node).toList

  override def getInEdgesOf(node: N): List[E] = inEdges.get(node).toList
}
