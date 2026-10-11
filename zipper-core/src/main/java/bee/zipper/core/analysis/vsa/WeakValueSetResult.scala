package bee.zipper.core.analysis.vsa

import bee.zipper.api.solver.sym.extend.SymbolicObject
import bee.zipper.api.solver.sym.term.*
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.vfg.*
import bee.zipper.core.analysis.model.cs.PathCallGraph
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** TChecker-style backward value set analysis.
  */
class WeakValueSetResult(vfg: Vfg)(implicit ctx: AnalysisContext) extends OnDemandValueSetResult {
  private val cache = mutable.Map.empty[CfgNode, Set[SymbolicValue]]

  override def ptsOf(stmt: CfgNode, v: CfgNode, partialEval: Boolean = false)(implicit
    pathCallGraph: Option[PathCallGraph] = None
  ): Set[SymbolicValue] = {
    eval(v, Set.empty)
  }

  override def clear(): Unit = cache.clear()

  private def eval(v: CfgNode, walk: Set[CfgNode]): Set[SymbolicValue] = {
    try {
      cache.getOrElseUpdate(
        v, {
          if (walk.contains(v)) Set.empty
          else {
            val newWalk = walk + v
            val expr    = ctx.translator.translate(v)
            expr match {
              case _: RealVar => backtrack(v, newWalk)
              case _: TmpVar =>
                v match {
                  case literal: Literal => Set(valueOf(literal))
                  case call: Call =>
                    call.name match {
                      case PhpOperators.concatOp => handleConcat(call, newWalk)
                      case Operators.alloc       => Set(SymbolicObject(call.typeFullName))
                      case _                     => Set.empty
                    }
                  case _ => Set.empty
                }
              case _ => Set.empty
            }
          }
        }
      )
    } catch {
      case _: StackOverflowError    => Set.empty
      case _: IllegalStateException => Set.empty
    }
  }

  private def backtrack(v: CfgNode, walk: Set[CfgNode]): Set[SymbolicValue] = {
    val preds = vfg.getPredsOf(v).toSet
    preds.flatMap(pred => eval(pred, walk))
  }

  private def handleConcat(call: Call, walk: Set[CfgNode]): Set[SymbolicValue] = {
    val args = call.args
    val lhs  = eval(args.head, walk).map(_.toString)
    val rhs  = eval(args(1), walk).map(_.toString)
    for {
      l <- lhs
      r <- rhs
    } yield StringLiteral(l + r)
  }

  private def valueOf(literal: Literal): SymbolicValue = {
    val value = literal.typeFullName match {
      case "int"    => IntLiteral(literal.getInt)
      case "string" => StringLiteral(literal.getString)
      case "bool"   => BoolLiteral(literal.getBool)
      case "null"   => IntLiteral(0)
      case "float"  => IntLiteral(literal.getFloat.toInt)
    }
    value
  }
}
