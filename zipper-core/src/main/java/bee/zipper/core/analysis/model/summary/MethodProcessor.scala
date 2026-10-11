package bee.zipper.core.analysis.model.summary

import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.bbcfg.{BBCfg, DefaultBBCfg}
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

class MethodProcessor(method: Method)(implicit ctx: AnalysisContext) {
  import ctx.translator.*

  val bbCfg: BBCfg = DefaultBBCfg.create(method, unrolling = true)

  val parameters: List[String] = method.parameter.map(translate(_).toString).toList

  val returnNames: Set[String] = {
    val returnNodes = method.methodReturn.toReturn
    returnNodes
      .flatMap(_.argumentOut)
      .map(translate(_).toString)
      .toSet
  }
}
