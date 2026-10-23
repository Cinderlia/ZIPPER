package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Adds the implicit taint of variables that are assigned under a tainted control structure.
  *
  * A variable does not have to receive tainted data to carry taint. In
  *
  * {{{
  * if ($item) {              // tainted guard
  *   $sql      = "..." . $item
  *   $isSearch = true       // implicit taint
  * }
  * if ($isSearch) { ... }   // control-flow dependency of the taint
  * }}}
  *
  * `$isSearch` is a flag whose value only depends on whether the tainted branch was taken, so a statement controlled by
  * it is control dependent on the tainted guard even though no tainted data reaches it.
  *
  * For every control structure that occurs on the path, or encloses a node of the path, the assignments of the
  * variables used in its condition are located by walking the CFG backwards. When such an assignment is itself guarded
  * by a tainted control structure, the guard's provenance is reused to build the slice `source ... -> tainted guard ->
  * assignment -> control structure -> ...` and the statement, the guard and the condition of the dependent control
  * structure are inserted into the path.
  */
final class ImplicitTaintEnhancer(emptySinkTracer: EmptySinkControlFlowTracer) {

  /** @param path
    *   a path produced by the regular taint analysis
    * @param knownPaths
    *   already computed paths of the same vulnerability kind; handed to the tracer to reuse known prefixes
    */
  def enhance(path: TaintPath, knownPaths: List[TaintPath]): TaintPath = {
    if (path.path.isEmpty) return path

    val pathIds   = path.path.map(_.id()).toSet
    val additions = mutable.LinkedHashSet.empty[CfgNode]

    candidateControls(path).foreach { control =>
      conditionVariableNames(control).foreach { variable =>
        definitionsOf(control, variable)
          .filterNot(definition => pathIds.contains(definition.id()))
          .foreach { definition =>
            emptySinkTracer.trace(definition, knownPaths).foreach { trace =>
              additions ++= trace
              additions += control
              additions ++= control.condition.ast.collectAll[CfgNode]
            }
          }
      }
    }

    val newNodes = additions.iterator.filterNot(node => pathIds.contains(node.id())).toList
    if (newNodes.isEmpty) path
    else {
      val sink     = path.path.last
      val before   = path.path.dropRight(1)
      val inserted = newNodes.sortBy(_.order)
      path.copy(path = before ++ inserted ++ List(sink))
    }
  }

  /** Control structures that may be controlled by an implicit taint: the ones on the path and the ones enclosing a path
    * node (e.g. the `if` around an `echo` sink).
    */
  private def candidateControls(path: TaintPath): List[ControlStructure] = {
    val controls = mutable.LinkedHashSet.empty[ControlStructure]
    path.path.foreach { node =>
      node match {
        case control: ControlStructure => controls += control
        case _                         =>
      }
      enclosingControls(node).foreach(controls += _)
    }
    controls.toList
  }

  /** Enclosing control structures of `node`, nearest first. */
  private def enclosingControls(node: CfgNode): List[ControlStructure] = {
    val controls         = mutable.ListBuffer.empty[ControlStructure]
    var current: AstNode = node
    var closest          = current.getClosest[ControlStructure]
    while (closest.nonEmpty) {
      controls += closest.get
      current = closest.get
      closest = current.getClosest[ControlStructure]
    }
    controls.toList
  }

  private def conditionVariableNames(control: ControlStructure): Set[String] =
    control.condition.ast.collectAll[Identifier].map(_.code).toSet

  /** Assignments that may define `variable` before `control` is evaluated.
    *
    * The CFG is walked backwards from the control's condition, so every definition whose value can reach the condition
    * is visited, including definitions inside the branches that join before the control structure. The
    * [[ControlStructure]] node itself is not part of the CFG, which is why the walk starts at its condition.
    */
  private def definitionsOf(control: ControlStructure, variable: String): List[CfgNode] = {
    val method   = control.method
    val result   = mutable.ListBuffer.empty[CfgNode]
    val worklist = mutable.Queue.empty[CfgNode]
    val visited  = mutable.Set.empty[Long]
    worklist ++= control.condition.cfgPrev

    while (worklist.nonEmpty) {
      val node = worklist.dequeue()
      if (visited.add(node.id()) && node.method.id() == method.id()) {
        node match {
          case call: Call if call.isGenericAssignment && call.argumentOption(1).exists(_.code == variable) =>
            result += call
          case _ => ()
        }
        worklist ++= node.cfgPrev
      }
    }
    result.toList
  }
}
