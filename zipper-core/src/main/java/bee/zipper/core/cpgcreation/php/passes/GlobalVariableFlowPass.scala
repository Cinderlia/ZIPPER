package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.analysis.defuse.globalvar.GlobalVariableDefUse
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}

class GlobalVariableFlowLayer(defUse: GlobalVariableDefUse) extends LayerCreator {
  override val overlayName: String = "GlobalVariableFlowLayer"

  override val description: String = "Add global variable value flow to DDG"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new GlobalVariableFlowPass(cpg, defUse)
    pass.createAndApply()
  }
}

object GlobalVariableFlowLayer {
  def run(cpg: Cpg, defUse: GlobalVariableDefUse): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new GlobalVariableFlowLayer(defUse)
    layer.run(context)
  }
}

class GlobalVariableFlowPass(cpg: Cpg, defUse: GlobalVariableDefUse) extends CpgPass(cpg) {
  override def run(builder: DiffGraphBuilder): Unit = {
    defUse.defines.foreach(x => {
      // `to` node is the statement that uses the `global var`
      val to = x._1._1
      // `from` node is the RIGHT side of the definition statement
      val opt: Option[CfgNode] = {
        val defStmt = x._2
        defStmt match {
          case call: Call if call.isGenericAssignment =>
            Some(call.argument(1))
          case _ => None
        }
      }
      opt match {
        case Some(from) =>
          val label = x._1._2
          FeatureTagger.bind(builder, to, GlobalDataDependency)
          builder.addEdge(from, to, EdgeTypes.REACHING_DEF)
        case None =>
      }
    })
  }
}
