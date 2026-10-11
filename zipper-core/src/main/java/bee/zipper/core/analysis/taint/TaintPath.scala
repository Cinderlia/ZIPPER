package bee.zipper.core.analysis.taint

import io.joern.dataflowengineoss.language.Path
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

/** Represented the taint path from sink to source if `order` is true
  */
case class TaintPath(kind: String, order: Boolean, path: List[CfgNode]) extends Iterable[CfgNode] {
  def source: CfgNode = if (order) path.head else path.last

  def sink: CfgNode = if (order) path.last else path.head

  override def iterator: Iterator[CfgNode] = path.iterator

  def prettyPrint: String = {
    Path.show.apply(Path(path))
  }
}
