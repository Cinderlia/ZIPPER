package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Reconstructs a taint path for sinks that no taint flow reaches.
  *
  * Control-structure mode reports every sink, so a sink without tainted input is currently described by itself only.
  * Such a sink is still guarded by control structures: the statements between the guard and the sink only execute when
  * the guard's condition holds. This tracer walks the CFG backwards from the sink and records the enclosing
  * [[ControlStructure]] of every node it meets, nearest first. The first control structure whose condition depends on a
  * taint source supplies the missing provenance, and the resulting path describes the chain `source ... -> condition ->
  * control structure -> sink`.
  *
  * Walking the CFG instead of the AST matters: the sink may be preceded by unrelated `if` statements that are not its
  * guards. Those are skipped because a candidate must both enclose a visited CFG node and dominate the sink in the AST.
  */
final class EmptySinkControlFlowTracer(taintSources: Set[CfgNode], provenance: TaintControlFlowProvenance) {
  private val controlCache = mutable.Map.empty[Long, Option[List[CfgNode]]]

  /** Builds a path ending with `sink`, or `None` when no enclosing control structure is tainted.
    *
    * @param sink
    *   a sink that is not the endpoint of any taint flow
    * @param knownPaths
    *   paths already computed for the same vulnerability kind; a control structure that already occurs on one of them
    *   reuses that prefix instead of tracing its sources again
    */
  def trace(sink: CfgNode, knownPaths: List[TaintPath]): Option[List[CfgNode]] = {
    nearestControls(sink).iterator
      .flatMap(control => controlPath(control, knownPaths).map(path => distinctNodes(path :+ sink)))
      .nextOption()
  }

  /** Enclosing control structures of the nodes met while walking the CFG backwards, nearest first.
    *
    * A node contributes its closest AST ancestor of type [[ControlStructure]]; visiting nodes in BFS order therefore
    * yields the control structures ordered by their CFG distance to the sink.
    *
    * Only control structures that dominate the sink are kept: in the AST the sink must be inside the control
    * structure's body. A statement that merely follows an `if` block is reached during the CFG walk but is not guarded
    * by it, and building a path through such a guard would be unsound.
    */
  private def nearestControls(sink: CfgNode): List[ControlStructure] = {
    val dominating = mutable.Set.empty[Long]
    enclosingControlIds(sink, dominating)

    val controls = mutable.LinkedHashSet.empty[ControlStructure]
    val worklist = mutable.Queue.empty[CfgNode]
    val visited  = mutable.Set.empty[Long]
    worklist += sink

    while (worklist.nonEmpty) {
      val node = worklist.dequeue()
      if (visited.add(node.id()) && node.method.id() == sink.method.id()) {
        node.getClosest[ControlStructure].filter(control => dominating.contains(control.id())).foreach(controls += _)
        worklist ++= predecessors(node)
      }
    }
    controls.toList
  }

  /** Collects the ids of all control structures that enclose `node`, nearest first. */
  private def enclosingControlIds(node: CfgNode, ids: mutable.Set[Long]): Unit = {
    var current: AstNode = node
    var closest          = current.getClosest[ControlStructure]
    while (closest.nonEmpty) {
      val control = closest.get
      ids += control.id()
      current = control
      closest = current.getClosest[ControlStructure]
    }
  }

  private def predecessors(node: CfgNode): Iterator[CfgNode] = node match {
    case _: Method => Iterator.empty
    case _         => node.cfgPrev
  }

  /** Path from a taint source to `control`.
    *
    * The data dependency is traced first so that the reused prefix can only ever be a path that actually reaches the
    * control's condition; an already known prefix is only a fallback when no source can be traced directly.
    */
  private def controlPath(control: ControlStructure, knownPaths: List[TaintPath]): Option[List[CfgNode]] = {
    controlCache.getOrElseUpdate(control.id(), traceControl(control).orElse(reusedPrefix(control, knownPaths)))
  }

  /** Reuse the prefix of an already computed path that ends at `control`. */
  private def reusedPrefix(control: ControlStructure, knownPaths: List[TaintPath]): Option[List[CfgNode]] = {
    knownPaths.iterator
      .flatMap { path =>
        val index = path.path.indexWhere(_.id() == control.id())
        if (index >= 0) Some(path.path.take(index + 1)) else None
      }
      .nextOption()
  }

  /** Data dependency from a source to the condition of `control`, extended by the control structure itself.
    *
    * When several sources reach the condition, the shortest chain is kept to avoid noisy reports.
    */
  private def traceControl(control: ControlStructure): Option[List[CfgNode]] = {
    taintSources.iterator
      .flatMap(source => provenance.dataPath(source, control))
      .toList
      .sortBy(_.size)
      .headOption
      .map(dataPath => distinctNodes(dataPath :+ control))
  }

  private def distinctNodes(nodes: List[CfgNode]): List[CfgNode] = {
    val seen = mutable.Set.empty[Long]
    nodes.filter(node => seen.add(node.id()))
  }
}
