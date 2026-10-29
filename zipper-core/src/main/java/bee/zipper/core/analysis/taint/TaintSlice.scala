package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

/** A user input that flows into (or controls) a sink. `param` is extracted from the source expression when possible,
  * e.g. `get_query_var("p")` / `$_GET["page_id"]` -> `p` / `page_id`.
  */
case class SliceSource(file: String, line: Int, code: String, param: Option[String])

/** A statement of the slice around the sink. */
case class SliceNode(file: String, line: Int, code: String)

/** All inputs and statements that are relevant for one sink: the union of every taint path that ends at it. */
case class TaintSlice(
  kind: String,
  sinkFile: String,
  sinkLine: Int,
  sinkCode: String,
  sources: List[SliceSource],
  nodeCount: Int,
  nodes: List[SliceNode],
  pathCount: Int
)

object TaintSliceBuilder {

  private val paramPatterns = List(
    """get_query_var\(\s*["']([^"']+)["']""".r,
    """\$_GET\[\s*["']([^"']+)["']""".r,
    """\$_POST\[\s*["']([^"']+)["']""".r,
    """\$_REQUEST\[\s*["']([^"']+)["']""".r,
    """\$_COOKIE\[\s*["']([^"']+)["']""".r
  )

  private def param(code: String): Option[String] =
    paramPatterns.view.flatMap(pattern => pattern.findFirstMatchIn(code)).headOption.map(_.group(1))

  private def fileOf(node: CfgNode): String =
    node.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse("")
  private def lineOf(node: CfgNode): Int = node.lineNumber.getOrElse(-1)

  /** Groups the paths by sink and merges them into one slice per sink: union of nodes and union of taint sources. */
  def build(paths: List[TaintPath], sources: Set[CfgNode]): List[TaintSlice] = {
    paths
      .groupBy(path => path.sink.id())
      .values
      .toList
      .map { group =>
        val sink  = group.head.sink
        val nodes = group.flatMap(_.path).distinctBy(_.id())
        val srcNodes = nodes
          .filter(node => sources.exists(_.id() == node.id()))
          .distinctBy(node => (fileOf(node), lineOf(node), node.code))
        TaintSlice(
          kind = group.head.kind,
          sinkFile = fileOf(sink),
          sinkLine = lineOf(sink),
          sinkCode = sink.code,
          sources = srcNodes.map(node => SliceSource(fileOf(node), lineOf(node), node.code, param(node.code))),
          nodeCount = nodes.size,
          nodes = nodes.map(node => SliceNode(fileOf(node), lineOf(node), node.code)),
          pathCount = group.size
        )
      }
      .sortBy(slice => (slice.sinkFile, slice.sinkLine))
  }
}
