package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Merges the paths of sinks that sit on the same straight-line CFG segment.
  *
  * Sinks are usually written as a block of consecutive statements, e.g. `prepare`, three `bindParam` calls and
  * `execute`. They share the same straight-line CFG segment, so they are reached by the same provenance and would be
  * reported once per statement with (almost) the same path.
  *
  * The segment of a sink is found by walking `cfgPrev` while the flow stays linear: the walk stops at a node with
  * several predecessors (a merge) or at a predecessor with several successors (a branch). All sinks whose walks end at
  * the same node belong to one segment and are reported together: their paths are concatenated, de-duplicated by node
  * id, and the deepest sink keeps its position at the end of the merged path.
  */
final class SinkGroupMerger {

  /** @param paths
    *   paths of one vulnerability kind
    * @return
    *   one path per straight-line CFG segment
    */
  def merge(paths: List[TaintPath]): List[TaintPath] = {
    val groups = mutable.LinkedHashMap.empty[(String, Long), mutable.ListBuffer[TaintPath]]
    paths.foreach { path =>
      groups.getOrElseUpdate((path.kind, segmentAnchor(path.sink)), mutable.ListBuffer.empty) += path
    }
    groups.values.map(group => mergeGroup(group.toList)).toList
  }

  /** Id of the node that identifies the straight-line CFG segment containing `sink`. */
  private def segmentAnchor(sink: CfgNode): Long = {
    var current = sink
    var anchor  = sink
    var walking = true

    while (walking) {
      val predecessors = predecessorsOf(current, sink)
      if (predecessors.size != 1) walking = false
      else {
        val predecessor = predecessors.head
        if (successorsOf(predecessor, sink).size > 1) walking = false
        else {
          anchor = predecessor
          current = predecessor
        }
      }
    }
    anchor.id()
  }

  private def predecessorsOf(node: CfgNode, sink: CfgNode): List[CfgNode] =
    node.cfgPrev.filter(_.method.id() == sink.method.id()).toList

  private def successorsOf(node: CfgNode, sink: CfgNode): List[CfgNode] =
    node.cfgNext.filter(_.method.id() == sink.method.id()).toList

  /** Concatenates the paths of one segment and de-duplicates their nodes.
    *
    * The path of the deepest sink is used as the backbone because its suffix is the part every other path shares. The
    * nodes contributed by the remaining paths are inserted before that final sink, so the merged path still ends at the
    * sink the cluster is named after.
    */
  private def mergeGroup(paths: List[TaintPath]): TaintPath = {
    if (paths.size == 1) return paths.head

    val ordered  = paths.sortBy(path => path.sink.lineNumber.getOrElse(0))
    val deepest  = ordered.last
    val backbone = deepest.path.dropRight(1)
    val sinkNode = deepest.path.last
    val extras   = ordered.dropRight(1).flatMap(_.path)
    deepest.copy(path = distinctNodes(backbone ++ extras ++ List(sinkNode)))
  }

  private def distinctNodes(nodes: List[CfgNode]): List[CfgNode] = {
    val seen = mutable.Set.empty[Long]
    nodes.filter(node => seen.add(node.id()))
  }
}
