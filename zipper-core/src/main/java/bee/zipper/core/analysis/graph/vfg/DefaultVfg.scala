package bee.zipper.core.analysis.graph.vfg

import bee.zipper.core.AnalysisContext
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import bee.zipper.util.graph.DotDumper
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

// simple-vfg related code

type SimpleVfgLabel = VarLabel | SimpleMemVarLabel

case class SimpleVfgNormalEdge(from: CfgNode, to: CfgNode, label: SimpleVfgLabel) extends VfgNormalEdge

case class SimpleVfgCallEdge(from: CfgNode, to: CfgNode, callsite: Call, label: SimpleVfgLabel) extends VfgCallEdge

case class SimpleVfgRetEdge(from: CfgNode, to: CfgNode, label: SimpleVfgLabel) extends VfgRetEdge

class DefaultVfg(cpg: Cpg)(implicit ctx: AnalysisContext) extends Vfg {
  collectDdgEdges().foreach(e => addEdge(e))
  collectCrossEdges().foreach(e => addEdge(e))

  private def collectDdgEdges(): Iterator[VfgEdge] = {
    // use the builtin DDG of joern to build vfg
    cpg.graph.allEdges
      .filter(_.label == EdgeTypes.REACHING_DEF)
      .collect {
        case e: flatgraph.Edge if e.dst.is[CfgNode] && e.src.is[CfgNode] =>
          // reversed
          (e.src.as[CfgNode], e.dst.as[CfgNode])
      }
      .filter { case (from, to) => isDdgNode(from) && isDdgNode(to) }
      .map { case (from, to) =>
        val label = labelOf(from)
        // the DDG of joern is intra-procedural. so there is only VfgNormalEdge in Vfg
        SimpleVfgNormalEdge(from, to, label)
      }
  }

  private def collectCrossEdges(): Iterator[VfgEdge] = {
    val edges = cpg.graph.allEdges
      .filter(_.label == EdgeTypes.CALL)
      .collect {
        case e: flatgraph.Edge if e.dst.is[Method] && e.src.is[Call] =>
          (e.src.as[Call], e.dst.as[Method])
      }
      .filterNot { case (_, to) =>
        to.name.startsWith("<operator>.") || PhpBuiltins.FuncNames.contains(to.name)
      }
      .toList
    val crossEdges = mutable.ListBuffer.empty[VfgEdge]
    edges.foreach { case (call, method) =>
      val parameters = method.parameter.toList
      val args       = call.args
      // add edge from argument to parameter
      args.zip(parameters).foreach { case (arg, parameter) =>
        val label = labelOf(arg)
        crossEdges += SimpleVfgCallEdge(arg, parameter, call, label)
      }
      // add edge from ret to callsite
      method.cfgNode.isReturn.foreach(ret => {
        ret.argumentOut.headOption match {
          case Some(x) =>
            val label = labelOf(x)
            crossEdges += SimpleVfgRetEdge(ret, call, label)
          case None =>
        }
      })
    }
    crossEdges.iterator
  }

  private def labelOf(from: CfgNode): SimpleVfgLabel = {
    ctx.translator.translate(from) match {
      case v: Var           => VarLabel(v)
      case mv: SimpleMemVar => SimpleMemVarLabel(List(mv))
      case _                => assert(false)
    }
  }

  private def isDdgNode(node: CfgNode): Boolean = {
    node match {
      case _: (Method | ControlStructure | FieldIdentifier | JumpTarget | MethodReturn) => false
      case _                                                                            => true
    }
  }

  override def toString: String = {
    val dumper = new DotDumper[CfgNode, VfgEdge](this)
    dumper.setNodePrinter(node => s"${node.code}-${node.getClass.getSimpleName}")
    dumper.setEdgePrinter {
      case e: SimpleVfgNormalEdge => e.label.toString
      case e: SimpleVfgCallEdge   => s"[C]${e.label.toString}"
      case e: SimpleVfgRetEdge    => s"[R]${e.label.toString}"
    }
    dumper.dump()
  }
}

object DefaultVfg {
  def create(cpg: Cpg)(implicit ctx: AnalysisContext): DefaultVfg = {
    ctx.cache.getOrElseUpdate(
      classOf[DefaultVfg],
      cpg, {
        val vfg = new DefaultVfg(cpg)
        vfg
      }
    )
  }
}
