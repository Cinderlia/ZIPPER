package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Adds control structures that affect a taint path or depend on its tainted values. */
final class ControlStructurePathEnhancer {
  def enhance(path: TaintPath, taintSources: Set[CfgNode]): TaintPath = {
    if (path.path.size < 2) return path

    val taintNodes    = path.path.toSet
    val insertions    = mutable.Map.empty[Int, mutable.LinkedHashSet[CfgNode]]
    val insertedNodes = mutable.Set.empty[CfgNode]

    var segmentStart = 0
    while (segmentStart < path.path.size) {
      val method = path.path(segmentStart).method
      var segmentEnd = segmentStart
      while (segmentEnd + 1 < path.path.size && path.path(segmentEnd + 1).method == method) {
        segmentEnd += 1
      }

      if (segmentEnd > segmentStart) {
        val segmentPathNodes = path.path.slice(segmentStart, segmentEnd + 1).toSet
        val segment         = cfgSegment(path.path(segmentStart), path.path(segmentEnd))
        val relevantControls = segment.controls.filter { control =>
          val currentSourceBranchNodes = controlsPathNodes(control, segmentPathNodes)
          val branchTaintedNodes = segment.nodes.filter { candidate =>
            controlsBranchNode(control, candidate) && dependsOnPath(candidate, taintNodes)
          }
          val conditionIsTaintedByAnySource = conditionDependsOnSources(control, taintSources, segment.nodes)
          conditionIsTaintedByAnySource && (currentSourceBranchNodes.nonEmpty || branchTaintedNodes.nonEmpty)
        }
        val conditionNodes = relevantControls.flatMap(_.condition.ast.collectAll[CfgNode]).distinct
        val conditionNodeSet = conditionNodes.toSet
        val controlNodeSet   = relevantControls.toSet
        val dependentBodyNodes = segment.nodes.filter { candidate =>
          relevantControls.exists(controlsBranchNode(_, candidate)) && dependsOnPath(candidate, taintNodes)
        }
        val dependentStatements = dependentBodyNodes.flatMap {
          case call: Call if call.isGenericAssignment => Some(call)
          case node                                    => node.getClosest[Call].filter(_.isGenericAssignment)
        }
        val additions = (segment.nodes.filter(node => controlNodeSet.contains(node) || conditionNodeSet.contains(node)) ++
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

    while (worklist.nonEmpty) {
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

  private def collectEnclosingControls(
    node: CfgNode,
    controls: mutable.LinkedHashSet[ControlStructure]
  ): Unit = {
    node match {
      case control: ControlStructure => controls += control
      case _                         =>
    }

    val visited = mutable.Set.empty[ControlStructure]
    var current: AstNode = node
    var closest = current.getClosest[ControlStructure]
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

  private def conditionDependsOnSources(
    control: ControlStructure,
    taintSources: Set[CfgNode],
    segmentNodes: List[CfgNode]
  ): Boolean = {
    val conditionNodes = control.condition.ast.collectAll[CfgNode].toList
    if (traceDependency(conditionNodes, taintSources, forward = false).matched.nonEmpty) return true

    val conditionVariables = control.condition.ast.collectAll[Identifier].map(_.code).toSet
    val assignments = segmentNodes.collect { case call: Call if call.isGenericAssignment => call }
    val taintedVariables = mutable.Set.empty[String]
    var changed           = true

    while (changed) {
      changed = false
      assignments.foreach { assignment =>
        val targetName = assignment.argumentOption(1).map(_.code)
        val value      = assignment.argumentOption(2)
        val valueIsTainted = value.exists { rhs =>
          taintSources.exists(source => source == rhs || rhs.ast.contains(source)) ||
          traceDependency(List(rhs), taintSources, forward = false).matched.nonEmpty ||
          rhs.ast.collectAll[Identifier].exists(identifier => taintedVariables.contains(identifier.code))
        }
        targetName.foreach { name =>
          if (valueIsTainted && taintedVariables.add(name)) changed = true
        }
      }
    }

    conditionVariables.exists(taintedVariables.contains)
  }

  private case class DependencyTrace(visited: List[CfgNode], matched: Option[CfgNode])

  private def traceDependency(
    startNodes: Iterable[CfgNode],
    targets: Set[CfgNode],
    forward: Boolean
  ): DependencyTrace = {
    val worklist = mutable.Queue.empty[CfgNode]
    val visited  = mutable.LinkedHashSet.empty[CfgNode]
    worklist ++= startNodes
    var matched = Option.empty[CfgNode]

    while (worklist.nonEmpty && matched.isEmpty) {
      val node = worklist.dequeue()
      if (visited.add(node)) {
        if (targets.contains(node)) matched = Some(node)
        else {
          val adjacent = if (forward) node.out(EdgeTypes.REACHING_DEF) else node.in(EdgeTypes.REACHING_DEF)
          adjacent.collectAll[CfgNode].foreach(worklist.enqueue(_))
        }
      }
    }
    DependencyTrace(visited.toList, matched)
  }

  private def controlsBranchNode(control: ControlStructure, node: CfgNode): Boolean = {
    control.whenTrue.ast.contains(node) || control.whenFalse.ast.contains(node)
  }

  private def dependsOnPath(node: CfgNode, pathNodes: Set[CfgNode]): Boolean = {
    val worklist = mutable.Queue(node)
    val visited  = mutable.Set.empty[CfgNode]

    while (worklist.nonEmpty) {
      val current = worklist.dequeue()
      if (visited.add(current)) {
        if (pathNodes.contains(current)) return true
        current.out(EdgeTypes.REACHING_DEF).collectAll[CfgNode].foreach(worklist.enqueue(_))
      }
    }
    false
  }
}
