package bee.zipper.core.cpgcreation

import flatgraph.DiffGraphBuilder
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.reflect.ClassTag

trait Tagger[V: ClassTag] {
  val Key: String

  /** serialize the value to a string representation
    */
  def serialize(value: V): String

  /** deserialize the string representation back to the value
    */
  def deserialize(repr: String): V

  private def newTag(value: V): NewTag = NewTag().name(Key).value(serialize(value))

  /** bind a tag with the given value to the given node
    */
  def bind(builder: DiffGraphBuilder, node: StoredNode, value: V): NewTag = {
    val tag = newTag(value)
    builder.addEdge(node, tag, EdgeTypes.TAGGED_BY)
    tag
  }

  /** check if the given node has a tag defined in this tagger
    */
  def hasTag(node: StoredNode): Boolean = node.tag.nameExact(Key).nonEmpty

  /** get all values of the tags bind to the given node
    */
  def value(node: StoredNode): Iterator[V] = node.tag.nameExact(Key).map(tag => deserialize(tag.value))
}
