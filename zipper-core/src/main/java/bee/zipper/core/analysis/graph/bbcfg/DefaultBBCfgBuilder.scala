package bee.zipper.core.analysis.graph.bbcfg

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.cfg.DefaultCfg
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.core.ir.RealVar
import bee.zipper.util.AnyExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, MethodReturn}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

class DefaultBBCfgBuilder(val cfg: DefaultCfg)(implicit ctx: AnalysisContext) extends BBCfgBuilder {
  import ctx.translator.translate

  private val entryToBB   = mutable.Map.empty[CfgNode, DefaultBasicBlock]
  private val visitedNode = mutable.Set.empty[CfgNode]
  private val visitedBB   = mutable.Set.empty[DefaultBasicBlock]
  private val nodeToBB    = mutable.Map.empty[CfgNode, DefaultBasicBlock]

  final def build(): DefaultBBCfg = {
    val entryBB  = collectBasicBlock(cfg.entry)
    val exitBB   = collectBasicBlock(cfg.exit)
    val edges    = mutable.Set.empty[DefaultBBEdge]
    val worklist = mutable.Queue.empty[DefaultBasicBlock]
    worklist += entryBB
    while (worklist.nonEmpty) {
      val bb = worklist.dequeue()
      if (!visitedBB.contains(bb)) {
        visitedBB += bb
        cfg
          .getSuccsOf(bb.nodes.last)
          .foreach(succ =>
            val succBB = collectBasicBlock(succ)
            edges += DefaultBBEdge(bb, succBB)
            worklist += succBB
          )
      }
    }
    buildBBCfg(entryBB, exitBB, edges, nodeToBB)
  }

  /** n -> d is a back edge if d dominates n and the edge from n to d exists
    */
  private def isBackEdge(prevBB: DefaultBasicBlock, succBB: DefaultBasicBlock): Boolean = {
    val prevNode = prevBB.nodes.last
    val succNode = succBB.nodes.head
    succNode.dominates.contains(prevNode)
  }

  private def collectBasicBlock(node: CfgNode): DefaultBasicBlock = {
    entryToBB.getOrElseUpdate(
      node, {
        val defs  = mutable.Set.empty[RealVar]
        val uses  = mutable.Set.empty[RealVar]
        val nodes = mutable.ListBuffer.empty[CfgNode]
        val queue = mutable.Queue.empty[CfgNode]

        def enqueue(node: CfgNode): Unit = {
          visitedNode.add(node)
          queue.enqueue(node)
        }

        enqueue(node)
        while (queue.nonEmpty) {
          val curNode = queue.dequeue()
          nodes += curNode
          uses ++= getUses(curNode)
          val preds = cfg.getPredsOf(curNode)
          val succs = cfg.getSuccsOf(curNode)
          if (succs.size == 1 && cfg.getPredsOf(succs.head).size == 1 && !succs.exists(_.is[MethodReturn])) {
            val succ = succs.head
            val opt  = getDef(succ)
            if (!visitedNode.contains(succ)) {
              opt match {
                case Some(define) =>
                  if (!defs.contains(define) && !uses.contains(define)) {
                    enqueue(succ)
                    defs += define
                  }
                case None => enqueue(succ)
              }
            }
          }
        }
        val bb = DefaultBasicBlock(nodes.toList, cfg.m)
        bb.nodes.foreach(node => nodeToBB += node -> bb)
        bb
      }
    )
  }

  private def buildBBCfg(
    entryBB: DefaultBasicBlock,
    exitBB: DefaultBasicBlock,
    edges: mutable.Set[DefaultBBEdge],
    nodeToBB: mutable.Map[CfgNode, DefaultBasicBlock]
  ): DefaultBBCfg = {
    val bbCfg = new DefaultBBCfg(cfg.m, entryBB.as[DefaultBasicBlock], exitBB.as[DefaultBasicBlock], nodeToBB.toMap)
    bbCfg.addNode(entryBB)
    bbCfg.addNode(exitBB)
    edges.foreach(edge => bbCfg.addEdge(edge))
    bbCfg.sort()
    bbCfg.getSortedNodes.zipWithIndex.foreach { case (bb, index) => bb.setOrder(index) }
    bbCfg
  }

  private def getUses(node: CfgNode): Set[RealVar] = {
    node match {
      case call: Call =>
        val args =
          if (call.isGenericAssignment) {
            val x = call.args
            if (x.isEmpty) List.empty
            else x.tail // tail method is invalid on empty list
          } else call.args
        args.map(translate).collect { case x: RealVar => x }.toSet
      case _ => Set.empty
    }
  }

  private def getDef(node: CfgNode): Option[RealVar] = {
    node match {
      case call: Call if call.isGenericAssignment =>
        call.argumentOption(1).map(translate) match {
          case Some(v: RealVar) => Some(v)
          case _                => None
        }
      case _ => None
    }
  }
}
