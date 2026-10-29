package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.nodes.*
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

/** Compact, LLM-oriented view of one sink reached from one source. The steps keep only significant nodes so the flow
  * reads like a story with an explicit source and sink.
  */
case class CompactFlow(kind: String, sink: String, source: String, param: Option[String], steps: List[String])

object CompactFlowBuilder {

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

  private def noise(code: String): Boolean = {
    val text = code.trim
    text.isEmpty || text == "RET" || text.startsWith("<unknown>") || text.startsWith("tmp") ||
    text.matches("""^"[^"]*"$""") || text.matches("""^'[^']*'$""") || text.matches("""^\d+(\.\d+)?$""")
  }

  private val contentFields = Set(
    "post_title",
    "post_content",
    "post_excerpt",
    "comment_content",
    "comment_author",
    "comment_author_email",
    "comment_author_url"
  )

  private def significant(node: CfgNode, sourceIds: Set[Long], sinkId: Long): Boolean =
    node.id() == sinkId || sourceIds.contains(node.id()) || (node match {
      case _: ControlStructure  => true
      case _: MethodParameterIn => true
      case call: Call =>
        val contentField =
          call.name == "<operator>.fieldAccess" && call
            .argumentOption(2)
            .exists(arg => contentFields.contains(arg.code))
        !noise(call.code) && (
          contentField ||
            !call.name.startsWith("<operator>.") ||
            call.name == "<operator>.assignment" ||
            call.name.contains("concat")
        )
      case _ => false
    })

  private def stepsOf(path: TaintPath, sourceIds: Set[Long]): List[String] = {
    val seen = scala.collection.mutable.Set.empty[(String, Int, String)]
    val out  = scala.collection.mutable.ListBuffer.empty[String]
    path.path.foreach { node =>
      if (significant(node, sourceIds, path.sink.id()) && !noise(node.code)) {
        val key = (fileOf(node), lineOf(node), node.code)
        if (seen.add(key)) {
          val role =
            if (sourceIds.contains(node.id())) "   <- source"
            else if (node.id() == path.sink.id()) "   <- sink"
            else
              node match {
                case _: ControlStructure => "   (guard)"
                case _: MethodParameterIn =>
                  val method = Option(node.method).map(_.name).getOrElse("?")
                  s"   (param of $method)"
                case call: Call if call.name == "<operator>.fieldAccess" => "   (field read)"
                case _                                                   => ""
              }
          out += s"${fileOf(node)}:${lineOf(node)}  ${node.code}$role"
        }
      }
    }
    out.toList
  }

  /** One flow per (sink, source): every source keeps its own dataflow, distinct routes are all preserved. */
  def build(paths: List[TaintPath], sources: Set[CfgNode]): List[CompactFlow] = {
    val sourceIds = sources.map(_.id())
    val bySink    = paths.groupBy(_.sink.id())

    bySink.values.toList
      .flatMap { group =>
        val sink = group.head.sink
        val flows = group.map { path =>
          val source = path.path.head
          CompactFlow(
            kind = path.kind,
            sink = s"${fileOf(sink)}:${lineOf(sink)}  ${sink.code}",
            source = s"${fileOf(source)}:${lineOf(source)}  ${source.code}",
            param = param(source.code),
            steps = stepsOf(path, sourceIds)
          )
        }
        // one representative flow per (sink, source): every input keeps its own dataflow, alternative routes of the
        // same input are collapsed into the most complete one
        flows
          .groupBy(flow => (flow.source, flow.param))
          .values
          .map(_.maxBy(_.steps.size))
          .toList
      }
      .sortBy(flow => (flow.sink, flow.source))
  }
}
