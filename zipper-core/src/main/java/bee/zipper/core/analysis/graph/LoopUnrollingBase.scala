package bee.zipper.core.analysis.graph

import bee.zipper.core.analysis.graph.cfg.CfgEdge
import bee.zipper.util.graph.{Edge, DefaultGraph}
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Block, CfgNode, ControlStructure}
import io.shiftleft.semanticcpg.language.*

/** Unrolling the loop in CFG once
  */
trait LoopUnrollingBase[E <: Edge[CfgNode], Cfg <: DefaultGraph[CfgNode, E]] {
  final def unroll(cfg: Cfg): Unit = {
    getControlStructures(cfg).foreach(c =>
      c.controlStructureType match {
        case ControlStructureTypes.FOR   => forStmt(c, cfg)
        case ControlStructureTypes.WHILE => whileStmt(c, cfg)
        case ControlStructureTypes.DO    => doWhileStmt(c, cfg)
        case _                           =>
      }
    )
  }

  /** The impl create specific CFG edge
    */
  protected def createEdge(from: CfgNode, to: CfgNode): E

  /** Provide ControlStructure that need to be processed
    */
  protected def getControlStructures(cfg: Cfg): Iterator[ControlStructure]

  private def forStmt(c: ControlStructure, cfg: Cfg): Unit = {
    // https://github.com/joernio/joern/blob/a997dc3f3c67a57c08cddf899a36c823cbcd5862/joern-cli/frontends/x2cpg/src/main/scala/io/joern/x2cpg/passes/controlflow/cfgcreation/CfgCreator.scala#L371
    val children        = c.astChildren.l
    val nLocals         = children.count(_.isLocal)
    val initOption      = children.find(_.order == nLocals + 1)
    val conditionOption = children.find(_.order == nLocals + 2)
    val increaseOption  = children.find(_.order == nLocals + 3)
    val bodyOption      = children.find(_.order == nLocals + 4)
    for {
      init          <- initOption
      condition     <- conditionOption
      increase      <- increaseOption
      body          <- bodyOption
      increaseLast  <- getLastCfgNode(increase)
      conditionLast <- getLastCfgNode(condition)
      bodyAst = body.ast.toSet
      backEdge  <- cfg.getOutEdgesOf(increaseLast).headOption
      outOfEdge <- cfg.getOutEdgesOf(conditionLast).find(e => !bodyAst.contains(e.to))
    } {
      cfg.removeEdge(backEdge)
      cfg.addEdge(createEdge(backEdge.from, outOfEdge.to))
    }
  }

  private def whileStmt(c: ControlStructure, cfg: Cfg): Unit = {
    // https://github.com/joernio/joern/blob/a997dc3f3c67a57c08cddf899a36c823cbcd5862/joern-cli/frontends/x2cpg/src/main/scala/io/joern/x2cpg/passes/controlflow/cfgcreation/CfgCreator.scala#L432
    val conditionOption = c.condition.headOption
    val trueOption      = c.whenTrue.headOption
    for {
      condition     <- conditionOption
      trueBody      <- trueOption
      conditionLast <- getLastCfgNode(condition)
      trueLast      <- getLastCfgNode(trueBody)
      trueAst = trueBody.ast.toSet
      backEdge  <- cfg.getOutEdgesOf(trueLast).find(e => !trueAst.contains(e.to))
      outOfEdge <- cfg.getOutEdgesOf(conditionLast).find(e => !trueAst.contains(e.to))
    } {
      cfg.removeEdge(backEdge)
      cfg.addEdge(createEdge(backEdge.from, outOfEdge.to))
    }
  }

  private def doWhileStmt(c: ControlStructure, cfg: Cfg): Unit = {
    // https://github.com/joernio/joern/blob/a997dc3f3c67a57c08cddf899a36c823cbcd5862/joern-cli/frontends/x2cpg/src/main/scala/io/joern/x2cpg/passes/controlflow/cfgcreation/CfgCreator.scala#L407
    val bodyOption      = c.astChildren.where(_.order(1)).headOption
    val conditionOption = c.condition.headOption
    for {
      body          <- bodyOption
      condition     <- conditionOption
      conditionLast <- getLastCfgNode(condition)
      bodyAst = body.ast.toSet
      backEdge <- cfg.getOutEdgesOf(conditionLast).find(e => bodyAst.contains(e.to))
    } {
      cfg.removeEdge(backEdge)
    }
  }

  private def getLastCfgNode(node: AstNode): Option[CfgNode] = {
    node match {
      case block: Block  => block.astChildren.collectAll[CfgNode].lastOption
      case node: CfgNode => Some(node)
      case _             => None
    }
  }
}
