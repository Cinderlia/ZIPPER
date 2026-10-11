package bee.zipper.core.analysis.dataflow.reachingdef

import bee.zipper.core.analysis.dataflow.ifds.{HerosICfg, IFDSSolver, IFDSTabulationProblem}
import bee.zipper.core.analysis.graph.icfg.DefaultICfgSparseTransformer
import heros.flowfunc.Identity
import heros.{DefaultSeeds, FlowFunction, FlowFunctions}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import java.util
import scala.jdk.CollectionConverters.*

class IFDSReachingDef[V](val herosICfg: HerosICfg, val utils: XUtils[V]) {
  private val icfg = herosICfg.icfg

  private type ReachingDef = (V, CfgNode)

  private val solver = new Solver(new Problem())

  def analyze(): ReachingDefResult = {
    pruneICfg()
    solver.solve()
    val map = icfg.getNodes.map(node => node -> solver.ifdsResultsAt(node).asScala.map(_._2).toList).toMap
    ReachingDefResult(map)
  }

  private def pruneICfg(): Unit = {
    // reserve iter-procedural edges
    utils.holder.relatedStmts ++= {
      val callsites  = icfg.getNodes.filter(herosICfg.isCallStmt)
      val successors = callsites.cfgNext
      val methods    = icfg.cpg.method.toList
      val entries    = methods.cfgFirst
      val returns    = methods.methodReturn
      callsites ++ successors ++ entries ++ returns
    }
    val sparseTransformer = new DefaultICfgSparseTransformer(icfg, utils.isRelatedStmt)
    sparseTransformer.transform()
    icfg.sort()
  }

  private class Solver(problem: Problem) extends IFDSSolver[ReachingDef](problem)

  private class Problem extends IFDSTabulationProblem[ReachingDef](herosICfg) {
    override def createFlowFunctionsFactory(): FlowFunctions[CfgNode, ReachingDef, Method] = {
      new FlowFunctions[CfgNode, ReachingDef, Method] {
        override def getNormalFlowFunction(curr: CfgNode, succ: CfgNode): FlowFunction[ReachingDef] =
          getNormalFlow(curr, succ)

        override def getCallFlowFunction(call: CfgNode, callee: Method): FlowFunction[ReachingDef] = Identity.v()

        override def getReturnFlowFunction(
          call: CfgNode,
          callee: Method,
          exitStmt: CfgNode,
          returnSite: CfgNode
        ): FlowFunction[ReachingDef] = Identity.v()

        override def getCallToReturnFlowFunction(call: CfgNode, returnSite: CfgNode): FlowFunction[ReachingDef] =
          Identity.v()
      }
    }

    private def getNormalFlow(curr: CfgNode, succ: CfgNode): FlowFunction[ReachingDef] = {
      val defs = utils.getDefVarsOf(curr)
      // indicate `curr` is not a definition statement
      if (defs.isEmpty) Identity.v()
      else
        (source: ReachingDef) => {
          if (source != zeroValue())
            if (defs.contains(source._1)) // re-definition
              util.Collections.emptySet()
            else
              util.Collections.singleton(source)
          else
            defs.map(definition => (definition, curr)).asJava
        }
    }

    override def createZeroValue(): ReachingDef = {
      val dummy = new Call(null, 0)
      (null.asInstanceOf[V], dummy)
    }

    override def initialSeeds(): util.Map[CfgNode, util.Set[ReachingDef]] =
      DefaultSeeds.make(herosICfg.getEntryStmts, zeroValue())
  }
}
