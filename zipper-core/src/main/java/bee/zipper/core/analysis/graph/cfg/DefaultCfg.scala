package bee.zipper.core.analysis.graph.cfg

import bee.zipper.core.AnalysisContext
import bee.zipper.util.AnyExtension.*
import bee.zipper.util.graph.DotDumper
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}
import io.shiftleft.semanticcpg.language.*

class DefaultCfg(val m: Method) extends Cfg {
  override def entry: CfgNode = m.cfgFirst.head

  override def exit: CfgNode = m.methodReturn

  collectCfgEdge().foreach(e => addEdge(e))

  private def collectCfgEdge(): Iterator[DefaultCfgEdge] = {
    (m.cfgNode ++ entry ++ exit)
      .flatMap(_.inE(EdgeTypes.CFG))
      .distinct
      .map(e => DefaultCfgEdge(e.src.as[CfgNode], e.dst.as[CfgNode]))
  }

  override def toString: String = {
    val dumper = new DotDumper[CfgNode, CfgEdge](this)
    dumper.setNodePrinter(_.code)
    dumper.dump()
  }
}

object DefaultCfg {
  def create(m: Method, unrolling: Boolean = false)(implicit ctx: AnalysisContext): DefaultCfg = {
    ctx.cache.getOrElseUpdate(
      classOf[DefaultCfg],
      (m, unrolling), {
        val cfg = new DefaultCfg(m)
        if (unrolling) {
          LoopUnrolling.unroll(cfg)
        }
        cfg
      }
    )
  }
}
