package bee.zipper.core.analysis.graph.icfg

import bee.zipper.core.AnalysisContext
import bee.zipper.util.AnyExtension.*
import bee.zipper.util.CollectionExtension.*
import bee.zipper.util.graph.DotDumper
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

class DefaultICfg(val cpg: Cpg, val domain: Set[Method] = Set.empty) extends ICfg {
  private val domainNodes      = domain.ast.extract[CfgNode].toSet
  private val reachableMethods = mutable.Set.empty[Method]

  reachableMethods ++= collectEntryMethods()

  private val (crossEdges, removeEdges) = collectCrossEdges()
  crossEdges.foreach(e => addEdge(e))
  collectCfgEdge().foreach(e => addEdge(e))

  def getReachableMethods: Set[Method] = reachableMethods.toSet

  private def collectEntryMethods(): List[Method] = cpg.method("<global>").toList

  private def collectCfgEdge(): Iterator[ICfgEdge] = {
    def isCfgNode(node: flatgraph.GNode): Boolean = !node.is[Method]

    val allCfgEdges =
      cpg.graph.allEdges
        .filter(_.label == EdgeTypes.CFG)
        .filter(e => isCfgNode(e.src))
        .map(edge => (edge.src.as[CfgNode], edge.dst.as[CfgNode]))
        .toSet

    val edges =
      allCfgEdges
        .diff(removeEdges)
        .map(e => ICfgNormalEdge(e._1, e._2))
        .iterator

    if (domain.isEmpty) edges
    else edges.filter(e => domainNodes.contains(e.from) && domainNodes.contains(e.to))
  }

  private def collectCrossEdges(): (Iterator[ICfgEdge], Set[(CfgNode, CfgNode)]) = {
    val phpOperators = Set("global", "isset", "print", "clone", "empty", "eval", "exit")

    def cpgCallEdges(): List[(Call, Method)] = {
      val edges = cpg.graph.allEdges
        .filter(_.label == EdgeTypes.CALL)
        .collect {
          case e: flatgraph.Edge if e.dst.is[Method] && e.src.is[Call] =>
            (e.src.as[Call], e.dst.as[Method])
        }
        .filterNot { case (_, to) =>
          to.name.startsWith("<operator>.") || PhpBuiltins.FuncNames.contains(to.name) || phpOperators.contains(to.name)
        }
      if (domain.isEmpty) edges.toList
      else edges.filter(e => domain.contains(e._2)).toList
    }
    val edges       = cpgCallEdges()
    val crossEdges  = mutable.ListBuffer.empty[ICfgEdge]
    val removeEdges = mutable.ListBuffer.empty[(CfgNode, CfgNode)]
    edges.foreach {
      case (call, method) if !method.isExternal =>
        reachableMethods += method
        reachableMethods += call.method
        method.cfgFirst.headOption match {
          case Some(calleeEntry) =>
            // step1. create call edge
            crossEdges += ICfgCallEdge(call, calleeEntry, method)
            call.cfgNext.foreach(succ =>
              // step2. create call to return edge
              crossEdges += ICfgCallToReturnEdge(call, succ)
              removeEdges += ((call, succ))
              // step3. create return edge
              crossEdges += ICfgRetEdge(method.methodReturn, succ, call)
            )
          case None =>
        }
      case _ =>
    }
    (crossEdges.iterator, removeEdges.toSet)
  }

  override def toString: String = {
    val dumper = new DotDumper[CfgNode, ICfgEdge](this)
    dumper.setNodePrinter(_.code)
    dumper.dump()
  }
}

object DefaultICfg {
  def create(cpg: Cpg, unrolling: Boolean = false)(implicit ctx: AnalysisContext): DefaultICfg = {
    ctx.cache.getOrElseUpdate(
      classOf[DefaultICfg],
      (cpg, unrolling), {
        val icfg = new DefaultICfg(cpg)
        if (unrolling) {
          LoopUnrolling.unroll(icfg)
        }
        icfg
      }
    )
  }
}
