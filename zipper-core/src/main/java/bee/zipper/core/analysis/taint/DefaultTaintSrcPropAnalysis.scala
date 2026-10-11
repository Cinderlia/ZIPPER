package bee.zipper.core.analysis.taint

import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.util.CollectionExtension.*
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

class DefaultTaintSrcPropAnalysis(vsa: ValueSetResult) extends TaintSrcPropAnalysis {
  override def analyze(taintPath: TaintPath): TaintSourceProperty = {
    val key       = getRequestKey(taintPath)
    val structure = getStructure(taintPath)
    TaintSourceProperty(key, structure)
  }

  private def getRequestKey(taintPath: TaintPath): String = {
    val source  = taintPath.source
    val unknown = "unknown"
    source match {
      case call: Call =>
        call.name match {
          case Operators.indexAccess =>
            call
              .argumentOption(2)
              .map(arg => {
                val keys = vsa.ptsOf(call, arg).extract[StringLiteral].map(_.value).toList
                keys match {
                  case List(key) => key
                  case _         => unknown
                }
              })
              .getOrElse(unknown)
          case _ => unknown
        }
      case _ => unknown
    }
  }

  private def getStructure(taintPath: TaintPath): InputStructure = {
    var prev: InputStructure = GeneralString()
    taintPath.path.foreach(node => {
      node.tag
        .name(InputStructureTag.Key)
        .value
        .foreach(value => {
          val x = InputStructureTag.Value.valueOf(value)
          x match {
            case InputStructureTag.Value.ToHttpArrayKey =>
              prev = HttpArrayKey()
            case InputStructureTag.Value.ToHttpArrayValue =>
              prev = HttpArrayValue(None, Some(prev))
            case _ =>
          }
        })
    })
    prev
  }
}
