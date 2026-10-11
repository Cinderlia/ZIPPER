package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.extend.*
import bee.zipper.core.analysis.defuse.mem.MemoryDefUse
import bee.zipper.core.analysis.model.ptr.ArrayIndexPtr
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import org.slf4j.LoggerFactory

import scala.collection.mutable

object ImplicitDataflowLayer {
  def run(cpg: Cpg, vsa: ValueSetResult, defUse: MemoryDefUse): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new ImplicitDataflowLayer(vsa, defUse)
    layer.run(context)
  }
}

private class ImplicitDataflowLayer(vsa: ValueSetResult, defUse: MemoryDefUse) extends LayerCreator {
  override val overlayName: String = "ImplicitDataflowPass"

  override val description: String = "Connect implicit dataflow edges introduced by PHP dynamic features"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new ImplicitDataflowPass(cpg, vsa, defUse)
    pass.createAndApply()
  }
}

class ImplicitDataflowPass(cpg: Cpg, vsa: ValueSetResult, defUse: MemoryDefUse) extends CpgPass(cpg) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    handleExtract(builder)
  }

  private def handleExtract(builder: DiffGraphBuilder): Unit = {
    // find the use point of given identifier from [[start]] node. For example:
    //    extract(array("x" => 1)); // start node
    //    if (...)
    //      $y = $x + 1; // $x here
    //    $z = $x + 2;   // $x here
    def findIdentifiers(start: CfgNode, name: String): List[CfgNode] = {
      val identifiers = mutable.ListBuffer.empty[CfgNode]
      val queue       = mutable.Queue.empty[CfgNode]
      queue += start
      val visited = mutable.Set.empty[CfgNode]
      while (queue.nonEmpty) {
        val node = queue.dequeue()
        if (!visited.contains(node)) {
          visited += node
          node match {
            case id: Identifier if id.name == name => identifiers += id
            case _                                 => queue ++= node.cfgNext
          }
        }
      }
      identifiers.toList
    }

    def impl(call: Call): Unit = {
      logger.info(s"Resolve `extract` for ${call.log}")
      // step1. find the values of the first argument of `extract` callsite
      val arrays = call.argumentOption(1) match {
        case Some(argument1) => vsa.ptsOf(call, argument1).collectAll[SymbolicArray | DummyObject].toList
        case None            => Iterator.empty.toList
      }

      // step2. build the map of `the name of identifier` to `the corresponding memory ptr`
      val nameToPtrs = arrays
        .flatMap(array =>
          val names = array.getConcrete.keys
            .filter(_.nonEmpty) // make sure key is not empty
            .filter(key =>
              val c = key.head
              c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' // is it an identifier ?
            )
          names.map(name => name -> ArrayIndexPtr(array, name))
        )
        .groupBy(_._1)

      // step3. connect dataflow edges
      nameToPtrs.foreach { case (name, memPtrs) =>
        val targets = findIdentifiers(call, name)
        val sources = memPtrs.flatMap(memPtr => defUse.getReachingDefSourcesOf(call, memPtr._2))
        for {
          source <- sources
          target <- targets
        } {
          builder.addEdge(source, target, EdgeTypes.REACHING_DEF, name)
        }
      }
    }

    val calls = cpg.call("extract").filter(_.receiver.isEmpty)
    calls.foreach(call => impl(call))
  }
}
