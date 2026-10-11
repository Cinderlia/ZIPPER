package bee.zipper.core.analysis.model.cs

import bee.zipper.core.analysis.taint.TaintPath
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Expression, Method}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.util.control.Breaks.{break, breakable}

/** A partial call graph maps methods to their call sites. It is constructed from a call stack to perform forward
  * context-sensitive value-set analysis.
  */
type PathCallGraph = Map[Method, Call]

object PathCallGraph {
  def empty: PathCallGraph = Map.empty

  /** Build a pathCallGraph for a node in the taint path. See [[CallStack.fromValueFlow]] for more details.
    */
  def fromValueFlow(taintPath: TaintPath, targetNode: CfgNode): PathCallGraph = {
    val stack = CallStack.fromValueFlow(taintPath, targetNode)
    stack.toPathCallGraph(targetNode.method)
  }
}

class CallStack {
  private val stack = mutable.Stack.empty[Call]

  def push(m: Call): Unit = {
    if (stack.isEmpty || stack.top != m)
      stack.push(m)
  }

  def pop(): Option[Call] = {
    if (stack.nonEmpty) Some(stack.pop())
    else None
  }

  /** Update the call stack by two adjacent nodes in taint path (value flow path).
    *
    * TODO: we need consider the nodes introduced by global/object data dependency in the future.
    */
  def updateByValueFlow(from: CfgNode, to: CfgNode): Unit = {
    // enter a function call
    if (from.isExpression && to.isParameter) {
      from.asInstanceOf[Expression].inCall.headOption.foreach(call => this.push(call))
      return
    }
    // leave a function body
    if (from.isReturn && to.isCall) {
      this.pop()
    }
  }

  def updateByControlFlow(from: CfgNode, to: CfgNode): Unit = ???

  /** Converts the current stack into a PathCallGraph for a given target Method. The method maps each method to its
    * corresponding callsite.
    */
  def toPathCallGraph(target: Method): PathCallGraph = {
    if (stack.isEmpty) Map.empty
    else {
      val localCallGraph = mutable.Map.empty[Method, Call]
      var current        = target
      val stackCopy      = mutable.Stack.from(stack)
      while (stackCopy.nonEmpty) {
        val callsite = stackCopy.pop()
        localCallGraph += current -> callsite
        current = callsite.method
      }
      localCallGraph.toMap
    }
  }

  override def toString: String = stack.toList.map(call => s"${call.code} @ ${call.method.name}").mkString(" -> ")
}

object CallStack {

  /** Build a callstack for a node in the taint path.
    *
    * It's useful when do context-sensitive VSA on a node (or sub-nodes of it, such as arguments of call node) in the
    * taint path
    */
  def fromValueFlow(taintPath: TaintPath, targetNode: CfgNode): CallStack = {
    val stack = new CallStack()
    breakable {
      taintPath.path.sliding(2).foreach {
        case List(prevNode, currNode) =>
          stack.updateByValueFlow(prevNode, currNode)
          if (currNode == targetNode)
            break
        case _ =>
      }
    }
    stack
  }
}
