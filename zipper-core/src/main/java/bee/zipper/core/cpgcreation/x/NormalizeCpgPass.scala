package bee.zipper.core.cpgcreation.x

import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}

private class NormalizeCpgLayer extends LayerCreator {
  override val overlayName: String = "NormalizeCpgLayer"

  override val description: String = "Normalize CPG to do static analysis"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new NormalizeCpgPass(cpg)
    pass.createAndApply()
  }
}

object NormalizeCpgLayer {
  def run(cpg: Cpg): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new NormalizeCpgLayer
    layer.run(context)
  }
}

class NormalizeCpgPass(cpg: Cpg) extends CpgPass(cpg) {
  override def run(builder: DiffGraphBuilder): Unit = {
    forCallsiteAsCondition(builder)
  }

  // for callsite like `if (check(...))`
  private def forCallsiteAsCondition(builder: DiffGraphBuilder): Unit = {
    val callsites =
      cpg.call
        .filter(isUserDefinedCall)
        .filter(call => call.cfgNext.size > 1)

    callsites.foreach { call =>
      call.getClosest[ControlStructure] match {
        case Some(cs) =>
          val m        = call.method
          val dummy    = mkDummy(call, builder)
          val outEdges = call.outE(EdgeTypes.CFG).toList
          outEdges.foreach(edge =>
            val to = edge.dst
            builder.addEdge(dummy, to, EdgeTypes.CFG)
            builder.removeEdge(edge)
          )
          builder.addEdge(call, dummy, EdgeTypes.CFG)
          // for obtaining dummy node from `m.cfgNode`
          builder.addEdge(m, dummy, EdgeTypes.CONTAINS)
          // for obtaining control structure from dummy node using `getClosest`
          builder.addEdge(cs, dummy, EdgeTypes.AST)
        case None =>
      }
    }
  }

  private def mkDummy(ctx: CfgNode, builder: DiffGraphBuilder): NewLiteral = {
    val dummy = NewLiteral()
      .typeFullName("string")
      .code("\"dummy\"")
      .lineNumber(ctx.lineNumber)
      .columnNumber(ctx.columnNumber)
    builder.addNode(dummy)
    dummy
  }

  private def isUserDefinedCall(c: Call): Boolean = {
    !c.name.startsWith("<operator") && !PhpBuiltins.FuncNames.contains(c.name)
  }
}
