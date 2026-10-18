package bee.zipper.core.analysis.taint

import io.joern.dataflowengineoss.language.Path
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

/** Represented the taint path from sink to source if `order` is true
  */
case class PathControlDependency(
  pathIndex: Int,
  controlType: String,
  file: String,
  line: Int,
  conditionCode: String,
  code: String
)

case class TaintPath(
  kind: String,
  order: Boolean,
  path: List[CfgNode],
  controlDependencies: List[PathControlDependency] = Nil
) extends Iterable[CfgNode] {
  def source: CfgNode = if (order) path.head else path.last

  def sink: CfgNode = if (order) path.last else path.head

  override def iterator: Iterator[CfgNode] = path.iterator

  def prettyPrint: String = {
    Path.show.apply(Path(path))
  }
}

object TaintPath {
  def withControlDependencies(
    kind: String,
    order: Boolean,
    path: List[CfgNode],
    extractor: ControlDependencyExtractor
  ): TaintPath = TaintPath(kind, order, path, extractor.forPath(path))

  def withControlDependencies(
    kind: String,
    order: Boolean,
    path: List[CfgNode],
    extractor: ControlDependencyExtractor,
    targetNodes: Set[CfgNode]
  ): TaintPath = TaintPath(kind, order, path, extractor.forPath(path, targetNodes))
}

class ControlDependencyExtractor(cpg: Cpg) {
  private lazy val controlStructuresByCondition = cpg.controlStructure.l.flatMap { control =>
    control.condition.l.map(_.id -> control)
  }.toMap

  def forPath(path: List[CfgNode], targetNodes: Set[CfgNode] = Set.empty): List[PathControlDependency] =
    path.zipWithIndex.flatMap { case (node, pathIndex) =>
      if (targetNodes.nonEmpty && !targetNodes.contains(node)) Nil
      else node.controlledBy.l.flatMap { condition =>
        val descriptor = controlStructuresByCondition
          .get(condition.id)
          .map { control =>
            (
              "CONTROL_STRUCTURE",
              control.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse(""),
              control.lineNumber.getOrElse(-1),
              condition.code,
              control.code
            )
          }
          .orElse {
            condition.astParent match {
              case conditional: Call if conditional.name == "<operator>.conditional" =>
                Some(
                  (
                    "CONDITIONAL_EXPRESSION",
                    conditional.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse(""),
                    conditional.lineNumber.getOrElse(-1),
                    condition.code,
                    conditional.code
                  )
                )
              case _ =>
                Some(
                  (
                    "CONTROL_PREDICATE",
                    condition.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse(""),
                    condition.lineNumber.getOrElse(-1),
                    condition.code,
                    condition.code
                  )
                )
            }
          }
        descriptor.map { case (controlType, file, line, conditionCode, code) =>
          PathControlDependency(pathIndex, controlType, file, line, conditionCode, code)
        }
      }
    }.distinct
}
