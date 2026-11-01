package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Calls whose callee cannot be resolved (or is an external/stub method) are expanded by the dataflow engine by trying
  * every argument as a possible output. That is the source of the "unresolved output arguments" explosion.
  *
  * This pass narrows such calls to the classic over-approximation "any argument may flow to the result": it adds a
  * REACHING_DEF edge from every argument (and the receiver) to the call node and records the call so that paths passing
  * through it can be marked as low confidence.
  */
object UnresolvedCallRegistry {
  private val ids = mutable.Set.empty[Long]

  def add(id: Long): Unit         = ids += id
  def contains(id: Long): Boolean = ids.contains(id)
  def size: Int                   = ids.size
  def clear(): Unit               = ids.clear()
}

class UnresolvedCallFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  override def run(builder: DiffGraphBuilder): Unit = {
    cpg.call.l.foreach { call =>
      val called = NoResolve.getCalledMethods(call).l
      val narrow = called.isEmpty || called.forall(method => method.isExternal || method.start.isStub.nonEmpty)
      if (narrow) {
        val froms = call.receiver.l ++ call.argument.l
        if (froms.nonEmpty) {
          UnresolvedCallRegistry.add(call.id())
          froms.foreach(from => builder.addEdge(from, call, EdgeTypes.REACHING_DEF))
        }
      }
    }
  }
}
