package bee.zipper.core.analysis.taint.sourcesink

import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}

/** The taint sink in IR can be identified using the taint sink specification
  */
trait TaintSink

/** Represents a call site where specific arguments need to be traced.
  * @param call
  *   the callsite
  * @param arguments
  *   arguments need to be traced
  */
case class CallArgumentSink(call: Call, arguments: List[CfgNode]) extends TaintSink

/** Represents a direct node that acts as a taint sink.
  */
case class DirectNodeSink(node: CfgNode) extends TaintSink
