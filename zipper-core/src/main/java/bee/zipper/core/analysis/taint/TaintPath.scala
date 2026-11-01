package bee.zipper.core.analysis.taint

import io.joern.dataflowengineoss.language.Path
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

/** Represented the taint path from sink to source if `order` is true
  */
case class TaintPath(
  kind: String,
  order: Boolean,
  path: List[CfgNode],
  sinkOverride: Option[CfgNode] = None,
  unresolved: Boolean = false,
  middleNode: Option[CfgNode] = None
) extends Iterable[CfgNode] {
  def source: CfgNode = if (order) path.head else path.last

  /** The real sink of the path. Control-flow enhancement may append nodes after it, so the sink is recorded explicitly
    * instead of being derived from the last element.
    */
  def sink: CfgNode = sinkOverride.getOrElse(if (order) path.last else path.head)

  /** Path up to (and including) the sink; trailing enhancement nodes are dropped. */
  def trimmed: TaintPath = {
    val index = path.indexWhere(_.id() == sink.id())
    if (index >= 0 && index < path.size - 1) copy(path = path.take(index + 1)) else this
  }

  override def iterator: Iterator[CfgNode] = path.iterator

  def prettyPrint: String = {
    Path.show.apply(Path(path))
  }
}
