package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Traces other taint sources that influence already-selected control structures. */
final class TaintControlFlowProvenance(taintSources: Set[CfgNode]) {
  private val cachedPaths = mutable.ListBuffer.empty[List[CfgNode]]

  def enhance(path: TaintPath): TaintPath = {
    if (path.path.isEmpty) return path

    val mainSource = path.source
    val result     = mutable.ArrayBuffer.from(path.path)
    val processedControls = mutable.Set.empty[Long]
    val worklist = mutable.Queue.empty[ControlStructure]
    worklist ++= path.path.collect { case control: ControlStructure => control }

    while (worklist.nonEmpty) {
      val control = worklist.dequeue()
      if (processedControls.add(control.id())) {
        taintSources.iterator.filterNot(_ == mainSource).foreach { source =>
          traceFor(source, control).foreach { nodes =>
            val insertionIndex = result.indexWhere(_.id() == control.id())
            if (insertionIndex >= 0) {
              val newNodes = nodes.filterNot(node => result.exists(_.id() == node.id()))
              if (newNodes.nonEmpty) result.insertAll(insertionIndex, newNodes)
              newNodes.collect { case nested: ControlStructure => nested }.foreach(worklist.enqueue(_))
            }
          }
        }
      }
    }

    path.copy(path = result.toList)
  }

  private def traceFor(source: CfgNode, control: ControlStructure): Option[List[CfgNode]] = {
    cachedPath(source, control).orElse {
      findDataPath(source, control).flatMap { dataPath =>
        val trace = buildTrace(source, control, dataPath)
        trace.foreach(cachePath)
        trace
      }
    }
  }

  private def cachedPath(source: CfgNode, control: ControlStructure): Option[List[CfgNode]] = {
    cachedPaths.iterator.flatMap { nodes =>
      val sourceIndex  = nodes.indexWhere(_.id() == source.id())
      val controlIndex = nodes.indexWhere(_.id() == control.id())
      if (sourceIndex >= 0 && controlIndex >= sourceIndex) Some(nodes.slice(sourceIndex, controlIndex + 1))
      else None
    }.take(1).toList.headOption
  }

  private def cachePath(path: List[CfgNode]): Unit = {
    val contained = cachedPaths.filter(existing => isSubsequence(existing, path))
    if (contained.nonEmpty) {
      cachedPaths --= contained
      cachedPaths += path
    } else if (!cachedPaths.exists(existing => isSubsequence(path, existing))) {
      cachedPaths += path
    }
  }

  private def isSubsequence(candidate: List[CfgNode], path: List[CfgNode]): Boolean = {
    var candidateIndex = 0
    path.foreach { node =>
      if (candidateIndex < candidate.size && candidate(candidateIndex).id() == node.id())
        candidateIndex += 1
    }
    candidateIndex == candidate.size
  }

  private def buildTrace(source: CfgNode, control: ControlStructure, dataPath: List[CfgNode]): Option[List[CfgNode]] = {
    val conditionNodes = control.condition.ast.collectAll[CfgNode].toList
    val start         = sourceAssignment(source).getOrElse(source)
    val controls      = controlsOnCfgRoute(start, control, conditionNodes.toSet)
    Some(distinctNodes(dataPath ++ controls ++ conditionNodes ++ List(control)))
  }

  private def findDataPath(source: CfgNode, control: ControlStructure): Option[List[CfgNode]] = {
    val conditionNodes = control.condition.ast.collectAll[CfgNode].toList
    findReachingDefPath(source, conditionNodes.toSet)
      .orElse(findAssignmentPath(source, control, conditionNodes))
  }

  private def findReachingDefPath(source: CfgNode, targets: Set[CfgNode]): Option[List[CfgNode]] = {
    if (targets.contains(source)) return Some(List(source))

    val worklist = mutable.Queue(source)
    val visited  = mutable.Set.empty[CfgNode]
    val parent   = mutable.Map.empty[CfgNode, CfgNode]
    var matched  = Option.empty[CfgNode]

    while (worklist.nonEmpty && matched.isEmpty) {
      val node = worklist.dequeue()
      if (visited.add(node)) {
        if (targets.contains(node)) matched = Some(node)
        else {
          node.out(EdgeTypes.REACHING_DEF).collectAll[CfgNode].foreach { successor =>
            if (!visited.contains(successor)) {
              parent.getOrElseUpdate(successor, node)
              worklist += successor
            }
          }
        }
      }
    }

    matched.map(target => reconstructPath(source, target, parent))
  }

  private def reconstructPath(
    source: CfgNode,
    target: CfgNode,
    parent: mutable.Map[CfgNode, CfgNode]
  ): List[CfgNode] = {
    val reversed = mutable.ListBuffer(target)
    var current  = target
    while (current != source && parent.contains(current)) {
      current = parent(current)
      reversed += current
    }
    reversed.reverse.toList
  }

  private def findAssignmentPath(
    source: CfgNode,
    control: ControlStructure,
    conditionNodes: List[CfgNode]
  ): Option[List[CfgNode]] = {
    val assignments = control.method.cfgNode.collectAll[Call].filter(_.isGenericAssignment).toList
    val taintedVariables = mutable.Map.empty[String, List[CfgNode]]
    var changed = true

    def addTaintedVariable(name: String, path: List[CfgNode]): Unit = {
      taintedVariables.get(name) match {
        case Some(existing) if existing.size <= path.size =>
        case _ =>
          taintedVariables.update(name, path)
          changed = true
      }
    }

    while (changed) {
      changed = false
      assignments.foreach { assignment =>
        val target = assignment.argumentOption(1)
        val value  = assignment.argumentOption(2)
        for {
          lhs <- target
          rhs <- value
          trace <- valueTrace(source, rhs, taintedVariables.toMap)
        } addTaintedVariable(lhs.code, distinctNodes(trace ++ List(assignment, lhs)))
      }
    }

    val conditionVariables = conditionNodes.collect { case identifier: Identifier => identifier }
    conditionVariables.iterator
      .flatMap(identifier => taintedVariables.get(identifier.code).map(trace => distinctNodes(trace ++ List(identifier))))
      .toList
      .sortBy(_.size)
      .headOption
  }

  private def valueTrace(
    source: CfgNode,
    rhs: CfgNode,
    taintedVariables: Map[String, List[CfgNode]]
  ): Option[List[CfgNode]] = {
    if (rhs == source || rhs.ast.contains(source)) Some(List(source, rhs))
    else {
      val variableTrace = rhs.ast.collectAll[Identifier]
        .flatMap(identifier => taintedVariables.get(identifier.code))
        .toList
        .sortBy(_.size)
        .headOption
      variableTrace.map(trace => distinctNodes(trace ++ List(rhs)))
        .orElse(findReachingDefPath(source, Set(rhs)))
    }
  }

  private def sourceAssignment(source: CfgNode): Option[Call] = {
    source.method.cfgNode.collectAll[Call]
      .filter(call => call.isGenericAssignment && call.argumentOption(2).exists(_.ast.contains(source)))
      .toList
      .sortBy(_.order)
      .headOption
  }

  private def controlsOnCfgRoute(
    start: CfgNode,
    target: ControlStructure,
    conditionNodes: Set[CfgNode]
  ): List[CfgNode] = {
    val worklist = mutable.Queue(start)
    val visited  = mutable.Set.empty[CfgNode]
    val controls = mutable.LinkedHashSet.empty[ControlStructure]
    var reached  = false

    while (worklist.nonEmpty && !reached) {
      val node = worklist.dequeue()
      if (visited.add(node)) {
        collectEnclosingControls(node).foreach(controls += _)
        if (node == target || conditionNodes.contains(node)) reached = true
        else {
          val successors = node match {
            case _: MethodParameterIn => node.method.cfgFirst
            case _                    => node.cfgNext
          }
          successors.foreach(worklist.enqueue(_))
        }
      }
    }

    controls.toList.filterNot(_ == target)
  }

  private def collectEnclosingControls(node: CfgNode): List[ControlStructure] = {
    val controls = mutable.ListBuffer.empty[ControlStructure]
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
    controls.toList
  }

  private def distinctNodes(nodes: List[CfgNode]): List[CfgNode] = {
    val seen = mutable.Set.empty[Long]
    nodes.filter(node => seen.add(node.id()))
  }
}
