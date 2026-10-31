package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Adds control structures that affect a taint path or depend on its tainted values. */
final class ControlStructurePathEnhancer {
  private val logger = org.slf4j.LoggerFactory.getLogger(this.getClass)
  def enhance(path: TaintPath, provenance: TaintControlFlowProvenance): TaintPath = {
    if (path.path.size < 2) return path

    val taintNodes = path.path.toSet
    // one reverse reachability pass over REACHING_DEF instead of a BFS per segment node
    val taintReachable = reachableFromTaint(taintNodes)
    val insertions     = mutable.Map.empty[Int, mutable.LinkedHashSet[CfgNode]]
    val insertedNodes  = mutable.Set.empty[CfgNode]

    var segmentStart = 0
    while (segmentStart < path.path.size) {
      val method     = path.path(segmentStart).method
      var segmentEnd = segmentStart
      while (segmentEnd + 1 < path.path.size && path.path(segmentEnd + 1).method == method) {
        segmentEnd += 1
      }

      if (segmentEnd > segmentStart) {
        val segmentPathNodes = path.path.slice(segmentStart, segmentEnd + 1).toSet
        val segment          = cfgSegment(path.path(segmentStart), path.path(segmentEnd))
        val relevantControls = segment.controls.filter { control =>
          val branchPathNodes = controlsPathNodes(control, segmentPathNodes)
          val branchDependentNodes = segment.nodes.filter { candidate =>
            controlsBranchNode(control, candidate) && taintReachable.contains(candidate.id())
          }
          val conditionIsTainted = provenance.conditionDependsOnPath(control, segmentPathNodes.map(_.id()).toSet) ||
            provenance.conditionDependsOnSources(control)
          conditionIsTainted && (branchPathNodes.nonEmpty || branchDependentNodes.nonEmpty)
        }
        val conditionNodes   = relevantControls.flatMap(_.condition.ast.collectAll[CfgNode]).distinct
        val conditionNodeSet = conditionNodes.toSet
        val controlNodeSet   = relevantControls.toSet
        val dependentBodyNodes = segment.nodes.filter { candidate =>
          relevantControls.exists(controlsBranchNode(_, candidate)) && taintReachable.contains(candidate.id())
        }
        val dependentStatements = dependentBodyNodes.flatMap {
          case call: Call if call.isGenericAssignment => Some(call)
          case node                                   => node.getClosest[Call].filter(_.isGenericAssignment)
        }
        val additions =
          (segment.nodes.filter(node => controlNodeSet.contains(node) || conditionNodeSet.contains(node)) ++
            dependentBodyNodes ++ dependentStatements ++ relevantControls ++ conditionNodes).distinct
        val insertionIndex = segmentEnd - 1
        val insertion      = insertions.getOrElseUpdate(insertionIndex, mutable.LinkedHashSet.empty[CfgNode])
        additions.foreach { candidate =>
          if (!taintNodes.contains(candidate) && insertedNodes.add(candidate)) insertion += candidate
        }
      }

      segmentStart = segmentEnd + 1
    }

    val result = mutable.ListBuffer.empty[CfgNode]
    path.path.zipWithIndex.foreach { case (node, index) =>
      result += node
      insertions.get(index).foreach(result ++= _)
    }
    path.copy(path = result.toList)
  }

  private case class CfgSegment(nodes: List[CfgNode], controls: List[ControlStructure])

  private def cfgSegment(from: CfgNode, to: CfgNode): CfgSegment = {
    val nodes    = mutable.LinkedHashSet.empty[CfgNode]
    val controls = mutable.LinkedHashSet.empty[ControlStructure]
    val worklist = mutable.Queue(from)
    val visited  = mutable.Set.empty[CfgNode]

    def successors(node: CfgNode): Iterator[CfgNode] = node match {
      case _: MethodParameterIn => node.method.cfgFirst
      case _                    => node.cfgNext
    }

    var budget = 50000
    while (worklist.nonEmpty && budget > 0) {
      budget -= 1
      val node = worklist.dequeue()
      if (visited.add(node)) {
        nodes += node
        collectEnclosingControls(node, controls)

        if (node != to) {
          successors(node).foreach(worklist.enqueue(_))
        }
      }
    }

    CfgSegment(nodes.toList, controls.toList)
  }

  private def collectEnclosingControls(node: CfgNode, controls: mutable.LinkedHashSet[ControlStructure]): Unit = {
    node match {
      case control: ControlStructure => controls += control
      case _                         =>
    }

    val visited          = mutable.Set.empty[ControlStructure]
    var current: AstNode = node
    var closest          = current.getClosest[ControlStructure]
    while (closest.nonEmpty && visited.add(closest.get)) {
      val control = closest.get
      controls += control
      current = control
      closest = current.getClosest[ControlStructure]
    }
  }

  private def controlsPathNodes(control: ControlStructure, pathNodes: Set[CfgNode]): List[CfgNode] = {
    pathNodes.toList.filter(node => control.whenTrue.ast.contains(node) || control.whenFalse.ast.contains(node))
  }

  private def controlsBranchNode(control: ControlStructure, node: CfgNode): Boolean = {
    control.whenTrue.ast.contains(node) || control.whenFalse.ast.contains(node)
  }

  /** All nodes that can reach one of `targets` through REACHING_DEF within a few hops and inside the method, computed
    * once per path.
    */
  private def reachableFromTaint(targets: Set[CfgNode]): Set[Long] = {
    val maxDepth = Integer.getInteger("zipper.controlflow.provenance.depth", 16).intValue()
    val reached  = mutable.Set.empty[Long]
    val queue    = mutable.Queue.empty[(CfgNode, Int)]
    targets.foreach(node => queue.enqueue((node, 0)))
    while (queue.nonEmpty) {
      val (node, depth) = queue.dequeue()
      if (reached.add(node.id()) && depth < maxDepth && !node.isInstanceOf[MethodParameterIn]) {
        node.in(EdgeTypes.REACHING_DEF).collectAll[CfgNode].foreach { previous =>
          if (previous.method.id() == node.method.id()) queue.enqueue((previous, depth + 1))
        }
      }
    }
    reached.toSet
  }

  private def dependsOnPath(node: CfgNode, pathNodes: Set[CfgNode]): Boolean = {
    val worklist = mutable.Queue(node)
    val visited  = mutable.Set.empty[CfgNode]
    var budget   = 20000

    while (worklist.nonEmpty && budget > 0) {
      budget -= 1
      val current = worklist.dequeue()
      if (visited.add(current)) {
        if (pathNodes.contains(current)) return true
        current.out(EdgeTypes.REACHING_DEF).collectAll[CfgNode].foreach(worklist.enqueue(_))
      }
    }
    false
  }
}
