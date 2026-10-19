package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Traces source-to-control-condition taint paths and recursively expands their control dependencies. */
final class TaintControlFlowTracer(
  taintSources: List[CfgNode],
  findSourceToConditionFlows: (CfgNode, List[CfgNode]) => List[List[CfgNode]],
  pathEnhancer: ControlStructurePathEnhancer
) {
  private val cache = mutable.ListBuffer.empty[List[CfgNode]]

  def expand(path: TaintPath): TaintPath = {
    val visitedPairs = mutable.Set.empty[(Long, Long)]
    path.copy(path = expandNodes(path.path, path.kind, Set.empty, visitedPairs))
  }

  private def expandNodes(
    nodes: List[CfgNode],
    kind: String,
    activeControls: Set[Long],
    visitedPairs: mutable.Set[(Long, Long)]
  ): List[CfgNode] = {
    val originalNodes = nodes.toSet
    val insertions    = mutable.LinkedHashMap.empty[Long, mutable.LinkedHashSet[CfgNode]]
    val processedControls = mutable.Set.empty[Long]

    nodes.collect { case control: ControlStructure => control }.foreach { control =>
      if (!activeControls.contains(control.id()) && processedControls.add(control.id())) {
        traceControl(control, kind, activeControls, visitedPairs).foreach { trace =>
          val insertion = insertions.getOrElseUpdate(control.id(), mutable.LinkedHashSet.empty[CfgNode])
          trace.foreach(node => if (!originalNodes.contains(node)) insertion += node)
        }
      }
    }

    val expanded = mutable.ListBuffer.empty[CfgNode]
    nodes.foreach { node =>
      insertions.get(node.id()).foreach(expanded ++= _)
      expanded += node
    }
    expanded.toList
  }

  private def traceControl(
    control: ControlStructure,
    kind: String,
    activeControls: Set[Long],
    visitedPairs: mutable.Set[(Long, Long)]
  ): List[List[CfgNode]] = {
    val conditionNodes = control.condition.ast.collectAll[CfgNode].toList.distinct
    if (conditionNodes.isEmpty) return List.empty

    taintSources.flatMap { source =>
      val cached = cachedPathFor(source, control)
      if (cached.nonEmpty) cached
      else {
        val pair = (source.id(), control.id())
        if (!visitedPairs.add(pair)) None
        else
          findSourceToConditionFlows(source, conditionNodes).flatMap { flow =>
            if (!flow.contains(source)) None
            else {
              val sourceToControl = if (flow.contains(control)) flow else flow :+ control
              val flowPath        = TaintPath(kind, order = true, sourceToControl)
              val enhanced        = pathEnhancer.enhance(flowPath, taintSources.toSet)
              val recursivelyExpanded = expandNodes(
                enhanced.path,
                kind,
                activeControls + control.id(),
                visitedPairs
              )
              Some(storeOrMerge(recursivelyExpanded))
            }
          }
      }
    }
  }

  private def cachedPathFor(source: CfgNode, control: ControlStructure): List[List[CfgNode]] = {
    cache.filter(path => path.contains(source) && path.contains(control)).toList
  }

  private def storeOrMerge(path: List[CfgNode]): List[CfgNode] = {
    val containedPaths = cache.filter(cached => containsPath(path, cached)).toList
    if (containedPaths.nonEmpty) {
      cache --= containedPaths
      val mergedNodes = mutable.LinkedHashSet.empty[CfgNode]
      mergedNodes ++= path
      containedPaths.foreach(mergedNodes ++= _)
      val mergedPath = mergedNodes.toList
      cache += mergedPath
      mergedPath
    } else {
      cache += path
      path
    }
  }

  private def containsPath(path: List[CfgNode], candidate: List[CfgNode]): Boolean = {
    candidate.nonEmpty && path.sliding(candidate.size).exists(_.toList == candidate)
  }
}
