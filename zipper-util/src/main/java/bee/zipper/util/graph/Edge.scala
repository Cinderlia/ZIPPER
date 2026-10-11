package bee.zipper.util.graph

trait Edge[Node] {
  def from: Node

  def to: Node

  override def toString: String = s"($from -> $to)"
}
