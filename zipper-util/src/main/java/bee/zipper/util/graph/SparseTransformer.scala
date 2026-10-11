package bee.zipper.util.graph

import scala.collection.mutable

/** This trait is used to build the sparse graph to boost the dataflow analysis.
  *
  * See TCS'02 `On sparse evaluation representations` mentioned in POPL'09 `Semi-Sparse Flow-Sensitive Pointer Analysis`
  */
trait SparseTransformer[N, E <: Edge[N]](graph: DefaultGraph[N, E], isMNode: N => Boolean) {
  private val mNodes     = mutable.Set.empty[N]
  private val dummyNodes = mutable.ListBuffer.empty[N]

  protected def newNormalEdge(from: N, to: N): E

  final def transform(): DefaultGraph[N, E] = {
    /* step 1 */
    // build G_p by removing all m-nodes and edges incident on them.
    val inEdgesOnMNodes  = mutable.MultiDict.empty[N, E]
    val outEdgesOnMNodes = mutable.MultiDict.empty[N, E]
    graph.getNodes
      .filter(isMNode)
      .foreach(node =>
        mNodes += node
        val inEdges = graph.getInEdgesOf(node)
        inEdges.foreach(edge => inEdgesOnMNodes += node -> edge)
        val outEdges = graph.getOutEdgesOf(node)
        outEdges.foreach(edge => outEdgesOnMNodes += node -> edge)
      )
    graph.removeNodes(mNodes)

    // find the strongly connected components (named X_1, ..., X_k) of G_p in topological sort order
    val sccList = graph.findSCCs(sort = true)

    // recover to G
    graph.addEdges(inEdgesOnMNodes.values)
    graph.addEdges(outEdgesOnMNodes.values)

    /* step 2 */
    // apply the T4 transformation to each Xi in G. This step will create single w_i node for each X
    sccList.foreach(scc => applyT4Transformer(graph, scc))

    /* step 3 */
    // visit w1 to wk of G in order and try to apply T2 transformation
    dummyNodes.foreach(w => applyT2Transformer(graph, w))

    graph
  }

  private def applyT4Transformer(graph: DefaultGraph[N, E], scc: Set[N]): Unit = {
    val w = scc.head // pick a node from SCC as dummy node
    dummyNodes += w
    val edgesToRemove = mutable.Set.empty[E]
    val newEdges      = mutable.Set.empty[E]
    if (scc.size == 1) {
      val inEdges  = graph.getInEdgesOf(w)
      val outEdges = graph.getOutEdgesOf(w)
      inEdges.foreach { inEdge =>
        edgesToRemove += inEdge
        newEdges += newNormalEdge(inEdge.from, w)
      }
      outEdges.foreach { outEdge =>
        edgesToRemove += outEdge
        newEdges += newNormalEdge(w, outEdge.to)
      }
    } else {
      scc.foreach(sccNode =>
        // replace any edge of the form u -> v, where u ∉ X and v ∈ X by the edge u -> w
        val inEdges = graph.getInEdgesOf(sccNode)
        inEdges
          .filterNot(e => scc.contains(e.from))
          .foreach(inEdge =>
            edgesToRemove += inEdge
            newEdges += newNormalEdge(inEdge.from, w)
          )
        // replace any edge of the form v -> u, where v ∈ X and u ∉ X by the edge w -> u
        val outEdges = graph.getOutEdgesOf(sccNode)
        outEdges
          .filterNot(e => scc.contains(e.to))
          .foreach(outEdge =>
            edgesToRemove += outEdge
            newEdges += newNormalEdge(w, outEdge.to)
          )
      )
      // delete any edges of the form u -> v, where u ∈ X and v ∈ X
      graph.removeNodes(scc - w)
    }
    graph.removeEdges(edgesToRemove)
    graph.addEdges(newEdges)
  }

  private def applyT2Transformer(graph: DefaultGraph[N, E], w: N): Unit = {
    // T2 is applicable to a node u iff (i) u is a p-node and, (ii) u has only one predecessor.
    val inEdges = graph.getInEdgesOf(w)
    if (inEdges.size == 1) {
      val outEdges = graph.getOutEdgesOf(w)
      val pred     = inEdges.head.from
      outEdges.foreach(outEdge =>
        val succ    = outEdge.to
        val newEdge = newNormalEdge(pred, succ)
        graph.addEdge(newEdge)
      )
      graph.removeNode(w)
    }
  }
}
