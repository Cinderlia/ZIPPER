package bee.zipper.core.analysis.taint

import bee.zipper.api.solver.sym.SymCast
import bee.zipper.api.solver.sym.extend.{DummyObject, SymbolicArray}
import bee.zipper.api.solver.sym.term.*
import bee.zipper.core.analysis.model.cs.CallStack
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{ControlStructureTypes, Operators}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Lightweight reachability analysis extended by constant checking
  *
  * See ISSTA'12 Static Memory Leak Detection Using Full-Sparse Value-Flow Analysis
  */
class ReachabilityAnalysis(
  vsa: ValueSetResult,
  reportCollector: Option[ReachabilityReportCollector] = None
) {
  private val flowToReachable = mutable.Map.empty[(CfgNode, CfgNode), Boolean]

  def isReachable(path: List[CfgNode], kind: Option[String] = None): Boolean = {
    val reportPathId = reportCollector.map(_.beginPath(path, kind))
    if (path.size == 1) true
    else {
      implicit val callstack: CallStack = new CallStack
      // check whether an unreachable path exists
      path.sliding(2).zipWithIndex.forall {
        case (List(from, to), pairIndex) if isInSameMethod(from, to) => // why we call `isBranchCondition` here? remove now
          callstack.updateByValueFlow(from, to)
          flowToReachable.get((from, to)) match {
            case Some(reachable) =>
              reportPathId.foreach { pathId =>
                reportCollector.foreach(
                  _.recordPair(pathId, pairIndex, reachable, cacheHit = true, guard = None)
                )
                reportCollector.foreach(_.recordCacheHit(pathId, pairIndex, reachable))
              }
              reachable
            case None =>
              val valueFlowCodes = path.map(_.code).toSet
              val guard = cfgGuard(from, to, valueFlowCodes, reportPathId.map(_ -> pairIndex))
              val simplified = guard match {
                case BoolLiteral(false) => false
                case _                  => true
              }
              flowToReachable += (from, to) -> simplified
              reportPathId.foreach(pathId =>
                reportCollector.foreach(
                  _.recordPair(
                    pathId,
                    pairIndex,
                    simplified,
                    cacheHit = false,
                    guard = Some(guard.toString)
                  )
                )
              )
              simplified
          }
        case (List(_, _), pairIndex) =>
          reportPathId.foreach(pathId =>
            reportCollector.foreach(
              _.recordPair(pathId, pairIndex, reachable = true, cacheHit = false, guard = None)
            )
          )
          true
        case _ => true
      }
    }
  }

  private def isInSameMethod(from: CfgNode, to: CfgNode): Boolean = {
    from.method == to.method
  }

  /** Build cfg guard in intra-procedural for given two **VFG** node
    *
    * @param from
    *   the source VFG node
    * @param to
    *   the dest VFG node
    * @param valueFlowCodes
    *   the value flow of taint path
    */
  private def cfgGuard(
    from: CfgNode,
    to: CfgNode,
    valueFlowCodes: Set[String],
    reportContext: Option[(Int, Int)]
  )(implicit callstack: CallStack): BoolTerm = {
    val debugVisits =
      if (reportCollector.exists(_.includesDebug)) Some(mutable.ListBuffer.empty[(CfgNode, String)]) else None

    def finish(guard: BoolTerm, stopReason: Option[String] = None): BoolTerm = {
      reportContext.foreach { case (pathId, pairIndex) =>
        reportCollector.foreach(
          _.recordBfs(
            pathId,
            pairIndex,
            debugVisits.fold(List.empty[(CfgNode, String)])(_.toList),
            guard != BoolLiteral(false),
            guard.toString,
            stopReason
          )
        )
      }
      guard
    }

    if (isMustBeConstantConditionalOperator(from, valueFlowCodes)) {
      return finish(BoolLiteral(false), Some("must-be-constant conditional"))
    }

    // node.cfgNext will return empty if the node is a parameter
    def cfgSuccessors(node: CfgNode): Iterator[CfgNode] = {
      node match {
        case parameter: MethodParameterIn => node.method.cfgFirst
        case _                            => node.cfgNext
      }
    }

    val nodeToGuard = mutable.Map.empty[CfgNode, BoolTerm] withDefaultValue BoolLiteral(true)
    val worklist    = mutable.Queue.empty[CfgNode]
    val visited     = mutable.Set.empty[CfgNode]

    worklist += from
    while (worklist.nonEmpty) {
      val node = worklist.dequeue()
      if (!visited.contains(node)) {
        visited += node
        val guard = Or.create(
          node.cfgPrev
            .map(pred =>
              val part1 = nodeToGuard(pred)
              val part2 = eguard(pred, node, valueFlowCodes)
              And.create(Set(part1, part2))
            )
            .toSet
        )
        nodeToGuard += node -> guard
        debugVisits.foreach(_ += node -> guard.toString)
        if (node == to) {
          return finish(guard)
        }
        cfgSuccessors(node).foreach(succ =>
          val succLine = succ.lineNumber.getOrElse(0)
          val toLine   = to.lineNumber.getOrElse(0)
          if (succLine <= toLine) {
            worklist += succ
          }
        )
      }
    }
    finish(BoolLiteral(true))
  }

  /** Get the guard of two adjacent CFG nodes (i.e. the CFG edge)
    *
    * @param from
    *   the source CFG node
    * @param to
    *   the dest CFG node
    * @param valueFlowCodes
    *   the value flow of taint path
    */
  private def eguard(from: CfgNode, to: CfgNode, valueFlowCodes: Set[String])(implicit
    callstack: CallStack
  ): BoolTerm = {
    val succs = from.cfgNext.toList
    if (succs.size == 1) BoolLiteral(true)
    else {
      whichBranch(from, to) match {
        case Some(x) =>
          val pts =
            if (isSkipCondition(from, to, valueFlowCodes)) Set(BoolLiteral(false))
            else {
              val callgraph = Some(callstack.toPathCallGraph(to.method))
              vsa
                .ptsOf(from, from)(callgraph)
                .filterNot(_.is[DummyObject])
                .map(SymCast.toBool)
            }
          // case1: the result of VSA is empty indicates that the value of condition cannot be inferred
          // case2: the size of result >= 1, we use `Or` to combine them (not `And` operator)
          val condition = if (pts.isEmpty) DummyObject.unknownSymbol else Or.create(pts)
          if (x)
            condition
          else
            Not.create(condition)
        case None => BoolLiteral(true)
      }
    }
  }

  // wrapper functions
  private def isSkipCondition(condition: CfgNode, to: CfgNode, valueFlowCodes: Set[String]): Boolean = {
    isConstantCheckingCondition(condition, to, valueFlowCodes)
    || isNonStringTypeChecking(condition, to, valueFlowCodes)
  }

  // check if the value flow is checked by this condition
  private def isValueFlowChecked(condition: CfgNode, valueFlowCodes: Set[String]): Boolean =
    valueFlowCodes.contains(condition.code)

  // determines if a node performs a constant value check
  private def isConstantChecking(node: CfgNode, valueFlowCodes: Set[String]): Boolean = {
    node match {
      case call: Call =>
        val argumentSize = call.argument.size
        call.name match {
          case "in_array" if argumentSize >= 2 =>
            // like `in_array($source, array('asc', 'desc'))`
            val arg1           = call.argument(1)
            lazy val isChecked = isValueFlowChecked(arg1, valueFlowCodes)
            lazy val isConstantArray = vsa
              .ptsOf(call, call.argument(2))
              .collectAll[SymbolicArray]
              .flatMap(_.getConcrete.values)
              .forall(_.is[StringLiteral | IntLiteral | BoolLiteral])
            isChecked && isConstantArray
          case Operators.equals | PhpOperators.identicalOp if argumentSize >= 2 && call.argument(2).is[Literal] =>
            // like `$x == 'string'`
            val arg1 = call.argument(1)
            isValueFlowChecked(arg1, valueFlowCodes)
          case Operators.logicalOr | Operators.logicalAnd =>
            // like `$x == "str1" || $x == "str2"`
            call.argument.exists(arg => isConstantChecking(arg, valueFlowCodes))
          case _ => false
        }
      case _ => false
    }
  }

  // checks if a conditional operator that must resolve to a constant
  private def isMustBeConstantConditionalOperator(node: CfgNode, valueFlowCodes: Set[String]): Boolean = {
    // like `$x = (in_array($_GET['ca_type'], array('asc', 'desc'))) ? $_GET['ca_type'] : 'asc';`
    node match {
      case call: Call if call.name == Operators.conditional && call.argument.size >= 3 =>
        val condition = call.argument(1)
        isConstantChecking(condition, valueFlowCodes)
      case _ => false
    }
  }

  private def isInputLengthLimitOperator(node: CfgNode, valueFlowCodes: Set[String], threshold: Int = 8): Boolean = {
    node match {
      case call: Call if call.name == Operators.conditional && call.argument.size >= 3 =>
        val condition = call.argument(1)
        isConstantChecking(condition, valueFlowCodes)
      case _ => false
    }
  }

  // check if the branch condition is a constant checking condition
  private def isConstantCheckingCondition(condition: CfgNode, to: CfgNode, valueFlowCodes: Set[String]): Boolean = {
    def handleSwitchCase(condition: CfgNode, to: CfgNode): Boolean = {
      // in this case, `condition` node is the switch primary condition, i.e. `switch (condition) { ... }`,
      // `to` node is jump target of the switch, i.e. `case ...: ...`,
      // we can get the **case condition** by collect the cfgNext of `to` node
      to.cfgNext.headOption match {
        case Some(caseCondition: Literal) => isValueFlowChecked(condition, valueFlowCodes)
        case _                            => false
      }
    }

    getControlStructure(condition) match {
      case Some(cs) =>
        cs.controlStructureType match {
          case ControlStructureTypes.SWITCH => handleSwitchCase(condition, to)
          case _                            => isConstantChecking(condition, valueFlowCodes)
        }
      case None => false
    }
  }

  private val nonStringCheckingBuiltins =
    Set("is_int", "is_integer", "is_long", "is_float", "is_double", "is_real", "is_numeric", "is_bool")

  // check if the branch condition is a non-string type checking condition
  private def isNonStringTypeChecking(condition: CfgNode, to: CfgNode, valueFlowCodes: Set[String]): Boolean = {
    condition match {
      case call: Call =>
        val name         = call.name
        val argumentSize = call.argument.size
        if (nonStringCheckingBuiltins.contains(name) && argumentSize >= 1) {
          // like `is_int($source)`
          val arg1 = call.argument(1)
          isValueFlowChecked(arg1, valueFlowCodes)
        } else false
      case _ => false
    }
  }

  private val controlCache = mutable.Map.empty[CfgNode, ControlStructure]

  private def getControlStructure(node: CfgNode): Option[ControlStructure] = {
    controlCache
      .get(node)
      .orElse {
        val controlOption = node.getClosest[ControlStructure]
        controlOption.foreach(controlCache.update(node, _))
        controlOption
      }
  }

  /** Determine whether the next node is in true branch or false branch of the conditional jump.
    *
    * @param condition
    *   condition expr of the conditional jump
    */
  private def whichBranch(condition: CfgNode, next: CfgNode): Option[Boolean] = {
    getControlStructure(condition).flatMap { control =>
      if (control.whenTrue.ast.contains(next)) Some(true)
      else if (control.whenFalse.ast.contains(next)) Some(false)
      else None
    }
  }

  /** Is the sub-ast node of condition
    */
  private def isBranchCondition(node: CfgNode): Boolean = {
    getControlStructure(node) match {
      case Some(control) => control.condition.ast.contains(node)
      case None          => false
    }
  }
}
