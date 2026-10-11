package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.analysis.defuse.mem.MemoryDefUse
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.ObjectDataDependency
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import org.slf4j.LoggerFactory

class MemoryFlowLayer(defUse: MemoryDefUse) extends LayerCreator {
  override val overlayName: String = "MemFlowLayer"

  override val description: String = "Add memory value flow to DDG"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new MemoryFlowPass(cpg, defUse)
    pass.createAndApply()
  }
}

object MemoryFlowLayer {
  def run(cpg: Cpg, defUse: MemoryDefUse): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new MemoryFlowLayer(defUse)
    layer.run(context)
  }
}

class MemoryFlowPass(cpg: Cpg, defUse: MemoryDefUse) extends CpgPass(cpg) {
  override def run(builder: DiffGraphBuilder): Unit = {
    defUse.defines.foreach(x => {
      // `to` node is the statement that uses the `MemPtr`
      val to = x._1._1
      // `from` node is the RIGHT side of the definition statement
      val opt: Option[CfgNode] = {
        val defStmt = x._2
        defStmt match {
          case call: Call if call.isGenericAssignment =>
            Some(call.argument(2))
          case _ => None
        }
      }
      opt match {
        case Some(from) =>
          val label = x._1._2.toString
          FeatureTagger.bind(builder, to, ObjectDataDependency)
          builder.addEdge(from, to, EdgeTypes.REACHING_DEF)
        case None =>
      }
    })
  }
}
