package bee.zipper.core.analysis.dataflow.reachingdef.mem

import bee.zipper.api.solver.sym.extend.*
import bee.zipper.api.solver.sym.term.*
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.reachingdef.{UtilsResultHolder, XUtils}
import bee.zipper.core.analysis.model.ptr.*
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.MemberAccess

private type ResultHolder = UtilsResultHolder[MemPtr]

class MemoryUtils(cpg: Cpg, vsa: ValueSetResult)(implicit ctx: AnalysisContext)
    extends XUtils[MemPtr](cpg, new ResultHolder) {
  import ctx.translator.translate

  private def getMemPtrs(call: Call): Set[MemPtr] = {
    def extractArguments(call: Call): Option[(Expression, Expression)] =
      for {
        arg1 <- call.argumentOption(1)
        arg2 <- call.argumentOption(2)
      } yield (arg1, arg2)

    def createPtrs[T](objs: Iterator[T], fields: Iterator[String], f: (T, String) => MemPtr): Iterator[MemPtr] = {
      val fieldsList = fields.toList
      for {
        obj   <- objs
        field <- fieldsList.iterator
      } yield f(obj, field)
    }

    val x: Iterator[MemPtr] = call.name match {
      case Operators.fieldAccess =>
        extractArguments(call) match {
          case Some((arg1, arg2)) =>
            val objs   = vsa.ptsOf(call, arg1).collectAll[SymbolicObject | DummyObject]
            val fields = vsa.ptsOf(call, arg2).collectAll[StringLiteral].map(_.value)
            createPtrs(objs, fields, ObjFieldPtr.apply)
          case _ => Iterator.empty
        }
      case Operators.indexAccess =>
        extractArguments(call) match {
          case Some((arg1, arg2)) =>
            val arrays = vsa.ptsOf(call, arg1).collectAll[SymbolicArray | DummyObject]
            val indexes = vsa.ptsOf(call, arg2).collect {
              case StringLiteral(value) => value
              case IntLiteral(value)    => value.toString
            }
            createPtrs(arrays, indexes, ArrayIndexPtr.apply)
          case _ => Iterator.empty
        }
      case _ => Iterator.empty
    }
    x.toSet
  }

  override protected def analyze(method: Method): ResultHolder = {
    val holder = new ResultHolder
    import holder.*

    method.cfgNode.foreach(node =>
      translate(node) match {
        case x: TmpVar if node.is[Call] =>
          val call = node.as[Call]
          call.name match {
            case _ if MemberAccess.isGenericMemberAccessName(call.name) =>
              val memPtrs = getMemPtrs(node.as[Call])
              if (memPtrs.nonEmpty) {
                relatedStmts += node
                memPtrs.foreach(memPtr => stmtToUseVars += node -> memPtr)
              }
            case "extract" => // for php builtin function `extract`
              relatedStmts += node
            case _ =>
          }
        case x: (InstanceFieldAccess | ArrayAccess) =>
          // x is the left of assignment
          node.inGenericAssignment.headOption match {
            case Some(assignment) =>
              val memPtrs = getMemPtrs(node.as[Call])
              if (memPtrs.nonEmpty) {
                relatedStmts += assignment
                memPtrs.foreach(memPtr =>
                  varToDefStmts += memPtr     -> assignment
                  defStmtToVars += assignment -> memPtr
                )
              }
            case _ =>
          }
        case _ =>
      }
    )

    holder
  }
}
