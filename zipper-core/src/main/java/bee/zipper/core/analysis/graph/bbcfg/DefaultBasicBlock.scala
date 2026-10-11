package bee.zipper.core.analysis.graph.bbcfg

import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}

class DefaultBasicBlock(val nodes: List[CfgNode], val m: Method) extends BasicBlock {
  private var _order: Int = 0

  override def setOrder(o: Int): Unit = {
    _order = o
  }

  override def order: Int = _order

  override def equals(obj: Any): Boolean = {
    obj match {
      case other: DefaultBasicBlock => nodes == other.nodes
      case _                        => false
    }
  }

  override def hashCode(): Int = nodes.hashCode
}
