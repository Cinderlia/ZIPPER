package bee.zipper.util.graph

import org.apache.commons.text.StringEscapeUtils

class DotDumper[N, E <: Edge[N]](graph: Graph[N, E]) {
  private val idMap                    = graph.getNodes.zipWithIndex.toMap
  private val builder                  = new StringBuilder()
  private var nodePrinter: N => String = _.toString
  private var edgePrinter: E => String = _ => ""

  def setNodePrinter(nodePrinter: N => String): Unit = {
    this.nodePrinter = (x: N) => {
      StringEscapeUtils.escapeJava(nodePrinter(x))
    }
  }

  def setEdgePrinter(edgePrinter: E => String): Unit = {
    this.edgePrinter = (e: E) => {
      StringEscapeUtils.escapeJava(edgePrinter(e))
    }
  }

  def dump(): String = {
    builder ++= "digraph G {\n"
    graph.getNodes.foreach(dumpNode)
    graph.getEdges.foreach(dumpEdge)
    builder ++= "}\n"
    builder.toString()
  }

  private def dumpNode(node: N): Unit = {
    builder ++= s"  ${idMap(node)}"
    dumpElement[N](node, nodePrinter)
  }

  private def dumpElement[T](element: T, printer: T => String): Unit = {
    builder ++= " ["
    val label = printer(element)
    builder ++= s"label = \"$label\"];\n"
  }

  private def dumpEdge(edge: E): Unit = {
    builder ++= s"${idMap(edge.from)} -> ${idMap(edge.to)}"
    dumpElement[E](edge, edgePrinter)
  }
}
