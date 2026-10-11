package bee.zipper.core.analysis.graph.bbcfg

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.cfg.DefaultCfg
import bee.zipper.util.AnyExtension.*
import bee.zipper.util.graph.DotDumper
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}
import io.shiftleft.semanticcpg.language.*

class DefaultBBCfg(
  val m: Method,
  val entry: DefaultBasicBlock,
  val exit: DefaultBasicBlock,
  val nodeToBB: Map[CfgNode, DefaultBasicBlock]
) extends BBCfg {
  override def bbOf(node: CfgNode): DefaultBasicBlock = nodeToBB.getOrElse(node, DefaultBasicBlock(List.empty, m))

  override def toString: String = {
    val dumper = new DotDumper[BasicBlock, BBEdge](this)
    dumper.setNodePrinter(bb =>
      val order      = bb.order.toString
      val statements = bb.nodes.map(_.code).mkString("\n")
      order + "\n" + statements
    )
    dumper.dump()
  }
}

object DefaultBBCfg {
  def create(m: Method, unrolling: Boolean = false)(implicit ctx: AnalysisContext): DefaultBBCfg = {
    ctx.cache.getOrElseUpdate(
      classOf[DefaultBBCfg],
      (m, unrolling), {
        val cfg     = DefaultCfg.create(m, unrolling)
        val builder = new DefaultBBCfgBuilder(cfg)
        builder.build()
      }
    )
  }
}
