package bee.zipper.core.analysis.taint

import flatgraph.DiffGraphBuilder
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{ExpressionBase, NewTag}

object InputStructureTag {
  val Key: String = "InputStructureTag"

  enum Value {
    case ToHttpArrayKey, ToHttpArrayValue, ToJsonObjectKey, ToJsonObjectValue
  }

  def newTag(value: Value): NewTag = NewTag().name(InputStructureTag.Key).value(value.toString)

  def bindTag(builder: DiffGraphBuilder, node: ExpressionBase, value: Value): NewTag = {
    val tag = newTag(value)
    builder.addEdge(node, tag, EdgeTypes.TAGGED_BY)
    tag
  }
}
