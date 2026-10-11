package bee.zipper.core.analysis.dataflow.reachingdef.globalvar

import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.dataflow.reachingdef.{UtilsResultHolder, XUtils}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

private type ResultHolder = UtilsResultHolder[String]

/** @param lightweight
  *   If true, only collect the global variables that are used in method (exclude global method)
  */
class GlobalVariableUtils(cpg: Cpg, vsa: ValueSetResult, lightweight: Boolean)(implicit ctx: AnalysisContext)
    extends XUtils[String](cpg, new ResultHolder) {
  import ctx.translator.translate

  private type GlobVar = String

  override protected def analyze(m: Method): ResultHolder = {
    val joernTempVariables = Set("iter_tmp0", "iter_tmp1", "iter_tmp2")

    val localDeclares = {
      // collect the left part of assignments like `$id = XXX;`.
      // note we only collect the uppermost scope of method. for example
      //     <?php
      //     $id = 1;   // collect this
      //     if (...)
      //       $id = 2; // ignore this
      //     ...
      val locals = m.block.astChildren.isCall.isAssignment.target.isIdentifier.map(_.name)
      locals.toSet
    }
    val globalDeclares = mutable.Set.empty[String]
    val holder         = new ResultHolder
    import holder.*

    def getGlobalAccessNames(call: Call, args: List[CfgNode]): Option[List[String]] = {
      args.headOption.collect {
        case base: Identifier if base.name == "GLOBALS" =>
          args.lift(1).toList.flatMap(index => vsa.ptsOf(call, index).collectAll[StringLiteral].map(_.value))
      }
    }

    def handleCall(call: Call, globalDeclares: mutable.Set[String]): Unit = {
      val args = call.args
      call.name match {
        case PhpOperators.global =>
          // global $a, $b;
          globalDeclares ++= args.collect { case id: Identifier => id.name }
        case Operators.indexAccess =>
          // $GLOBALS['a']
          getGlobalAccessNames(call, args).foreach { indexes =>
            indexes.foreach(index => stmtToUseVars += call -> index)
            relatedStmts += call
          }
        case Operators.assignment =>
          def isUsingGlobalVar(idName: String): Boolean = {
            if (joernTempVariables.contains(idName)) false
            else globalDeclares.contains(idName) || m.name == "<global>"
          }

          translate(args.head) match {
            case ac: ArrayAccess =>
              // $GLOBALS['a'] = XXX;
              getGlobalAccessNames(call, args).foreach { indexes =>
                indexes.foreach { index =>
                  defStmtToVars += call  -> index
                  varToDefStmts += index -> call
                }
                relatedStmts += call
              }
            case sfa: StaticFieldVar =>
              // self::$data = XXX;
              val name = sfa.toString
              defStmtToVars += call -> name
              varToDefStmts += name -> call
              relatedStmts += call
            case v: Var if isUsingGlobalVar(v.name) =>
              // global $a;
              // $a = XXX;
              defStmtToVars += call   -> v.name
              varToDefStmts += v.name -> call
              relatedStmts += call
            case _ =>
          }
        case _ =>
          def isUsingGlobalVar(idName: String): Boolean = {
            if (joernTempVariables.contains(idName)) false
            else
              globalDeclares.contains(idName)
              || !lightweight && (m.name == "<global>" && !localDeclares.contains(idName))
          }

          val idNames = args.collect { case id: Identifier => id.name -> id }
          idNames.foreach { case (idName, id) =>
            if (isUsingGlobalVar(idName)) {
              stmtToUseVars += id -> idName
              relatedStmts += id
            }
          }
      }
    }

    def handleReturn(ret: Return, globalDeclares: mutable.Set[String]): Unit = {
      // global $a;
      // return $a;
      val idNames = ret.argumentOut.collect { case id: Identifier => id.name -> id }
      idNames.foreach { case (idName, id) =>
        if (globalDeclares.contains(idName)) {
          stmtToUseVars += id -> idName
          relatedStmts += id
        }
      }
    }

    def handleStaticFieldVar(node: CfgNode, sfv: StaticFieldVar): Unit = {
      stmtToUseVars += node -> sfv.toString
      relatedStmts += node
    }

    m.cfgNode
      .sortBy(_.order)
      .foreach(node => {
        translate(node) match {
          case sfv: StaticFieldVar => handleStaticFieldVar(node, sfv)
          case tmpVar: TmpVar =>
            node match {
              case call: Call  => handleCall(call, globalDeclares)
              case ret: Return => handleReturn(ret, globalDeclares)
              case _           =>
            }
          case _ =>
        }
      })

    holder
  }
}
