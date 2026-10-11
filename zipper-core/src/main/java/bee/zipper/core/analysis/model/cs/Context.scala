package bee.zipper.core.analysis.model.cs

import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

trait Context {
  def length: Int

  def push(call: Call): Context
}

case class ForwardContext(callstring: List[Call], k: Int = 2) extends Context {
  def length: Int = callstring.length

  def push(call: Call): Context = {
    val updatedCallString = (callstring ++ call).take(k)
    ForwardContext(updatedCallString, k)
  }

  override def toString: String = callstring.map(call => call.code).mkString(" -> ")
}
