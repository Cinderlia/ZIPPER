package bee.zipper.core.analysis.dataflow.iteration

import bee.zipper.core.AnalysisContext
import bee.zipper.core.ir.CpgNodeExecutor
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

trait TransferCtx[Fact] {
  def in: Fact

  def out: Fact
}

trait TransferFunction[Ctx](implicit x: AnalysisContext) extends CpgNodeExecutor[Ctx] {
  def apply(node: CfgNode, ctx: Ctx): Unit = {
    execute(node, ctx)
  }
}
