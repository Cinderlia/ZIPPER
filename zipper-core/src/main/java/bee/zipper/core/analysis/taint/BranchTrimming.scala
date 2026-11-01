package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Drops nodes that belong to the branch opposite to the one reaching the sink.
  *
  * A path may contain statements from both sides of an `if`/`else if` (for example two alternatives that set the same
  * flag). Such a path is not feasible: symbolic execution would combine two mutually exclusive branches. For every
  * control structure on the path, the branch that contains the sink is kept and the other branch is removed; when the
  * sink is outside both branches, the branch that appears first after the control on the path is kept.
  */
object BranchTrimming {

  def trim(path: TaintPath): Option[TaintPath] = {
    if (path.path.size < 2) return Some(path)

    val nodes = path.path

    def enclosing(node: CfgNode): List[ControlStructure] = {
      val result  = mutable.ListBuffer.empty[ControlStructure]
      val visited = mutable.Set.empty[ControlStructure]
      var current: AstNode = node match {
        case control: ControlStructure => control
        case other                     => other
      }
      var closest = current.getClosest[ControlStructure]
      while (closest.nonEmpty && visited.add(closest.get)) {
        result += closest.get
        current = closest.get
        closest = current.getClosest[ControlStructure]
      }
      result.toList
    }

    // Nested controls (else-if chains) are often not on the path themselves; collect their ancestors so that
    // mutually exclusive branches can still be recognized.
    val controls = nodes.flatMap(enclosing).distinctBy(_.id())
    val dropped  = mutable.Set.empty[Long]

    controls.foreach { control =>
      val trueIds  = control.whenTrue.ast.map(_.id()).toSet
      val falseIds = control.whenFalse.ast.map(_.id()).toSet
      val inTrue   = nodes.filter(node => trueIds.contains(node.id())).map(_.id()).toSet
      val inFalse  = nodes.filter(node => falseIds.contains(node.id())).map(_.id()).toSet

      if (inTrue.nonEmpty && inFalse.nonEmpty) {
        val sinkInTrue  = trueIds.contains(path.sink.id())
        val sinkInFalse = falseIds.contains(path.sink.id())
        if (sinkInTrue && !sinkInFalse) dropped ++= inFalse
        else if (sinkInFalse && !sinkInTrue) dropped ++= inTrue
        else {
          val index = nodes.indexWhere(_.id() == control.id())
          nodes.drop(index + 1).headOption.foreach { next =>
            if (trueIds.contains(next.id())) dropped ++= inFalse
            else if (falseIds.contains(next.id())) dropped ++= inTrue
          }
        }
      }
    }

    if (dropped.isEmpty) Some(path)
    else {
      val kept = nodes.filterNot(node => dropped.contains(node.id()))
      if (kept.isEmpty || !kept.exists(_.id() == path.source.id())) None
      else Some(path.copy(path = kept))
    }
  }
}
