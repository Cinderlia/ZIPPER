package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Keeps only the part of a taint path that can belong to one feasible execution.
  *
  * A transition between two consecutive nodes is feasible when the nodes are in the same method and the first reaches
  * the second through CFG successors, when it is a call into a parameter, when it is a return to the caller, or when
  * the engine recorded a direct dataflow edge between them. Dataflow always wins: a direct REACHING_DEF edge is
  * accepted even if the CFG/call relation is not obvious. When a transition is not feasible the path is cut at that
  * point and only the suffix that still reaches the sink is kept.
  */
object PathFeasibility {
  private val maxCfgNodes = 4000

  /** Keeps the dataflow backbone plus enhancement nodes that remain connected to it. Dataflow nodes are always kept
    * (dataflow wins on conflict); an added node survives only when it is reachable from a dataflow node through
    * feasible transitions.
    */
  def keepConnected(path: TaintPath): TaintPath = {
    if (path.dataflowNodes.isEmpty || path.path.isEmpty) return path

    val nodes      = path.path
    val rawMethods = nodes.filter(node => path.dataflowNodes.contains(node.id())).map(_.method.id()).toSet
    // keep the dataflow backbone and everything added inside the methods it already touches; cross-method additions
    // must be anchored to a kept node through a feasible call/return/CFG transition
    val keep = scala.collection.mutable.Set.empty[Long] ++ path.dataflowNodes ++
      nodes.filter(node => rawMethods.contains(node.method.id())).map(_.id())
    var changed = true
    while (changed) {
      changed = false
      var index = 0
      while (index < nodes.size) {
        val node = nodes(index)
        if (!keep.contains(node.id())) {
          val previousOk = index > 0 && keep.contains(nodes(index - 1).id()) && feasible(nodes(index - 1), node)
          val nextOk =
            index < nodes.size - 1 && keep.contains(nodes(index + 1).id()) && feasible(node, nodes(index + 1))
          if (previousOk || nextOk) {
            keep += node.id()
            changed = true
          }
        }
        index += 1
      }
    }

    path.copy(path = nodes.filter(node => keep.contains(node.id())))
  }

  private def sameMethod(a: CfgNode, b: CfgNode): Boolean =
    Option(a.method).exists(_.id() == b.method.id())

  private def hasDataEdge(a: CfgNode, b: CfgNode): Boolean =
    a.out(EdgeTypes.REACHING_DEF).exists(_.id() == b.id())

  private def cfgReaches(from: CfgNode, to: CfgNode): Boolean = {
    val visited = mutable.Set.empty[Long]
    val queue   = mutable.Queue.empty[CfgNode]
    queue.enqueue(from)
    while (queue.nonEmpty && visited.size < maxCfgNodes) {
      val node = queue.dequeue()
      if (visited.add(node.id())) {
        if (node.id() == to.id()) return true
        if (node.method.id() == from.method.id()) node.cfgNext.foreach(queue.enqueue)
      }
    }
    false
  }

  private def isCallToParameter(a: CfgNode, b: CfgNode): Boolean =
    a.isInstanceOf[Call] && b.isInstanceOf[MethodParameterIn]

  private def isReturn(a: CfgNode, b: CfgNode): Boolean =
    a.isInstanceOf[MethodReturn] || b.isInstanceOf[MethodReturn]

  private def feasible(a: CfgNode, b: CfgNode): Boolean =
    hasDataEdge(a, b) ||
      (sameMethod(a, b) && cfgReaches(a, b)) ||
      isCallToParameter(a, b) ||
      isReturn(a, b)
}
