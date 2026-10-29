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

/** Per-sink graph for symbolic execution: every sink owns its nodes and typed edges (data, call argument, return, field
  * read, control) together with its sources and guards.
  */
case class SinkGraphNode(id: String, at: String, code: String, kind: String)
case class SinkGraphEdge(from: String, to: String, kind: String)
case class SinkGraph(
  kind: String,
  sink: String,
  params: List[String],
  sources: List[String],
  guards: List[String],
  nodes: List[SinkGraphNode],
  edges: List[SinkGraphEdge]
)

object SinkGraphBuilder {

  private def fileOf(node: CfgNode): String =
    node.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse("")
  private def lineOf(node: CfgNode): Int  = node.lineNumber.getOrElse(-1)
  private def atOf(node: CfgNode): String = s"${fileOf(node)}:${lineOf(node)}"

  private val contentFields = Set(
    "post_title",
    "post_content",
    "post_excerpt",
    "comment_content",
    "comment_author",
    "comment_author_email",
    "comment_author_url"
  )

  private def isContentField(call: Call): Boolean =
    call.name == "<operator>.fieldAccess" && call.argumentOption(2).exists(arg => contentFields.contains(arg.code))

  private def noise(code: String): Boolean = {
    val text = code.trim
    text.isEmpty || text == "RET" || text.startsWith("<unknown>") || text.startsWith("tmp")
  }

  private def nodeKind(node: CfgNode, sourceIds: Set[Long], sinkId: Long): String =
    if (node.id() == sinkId) "sink"
    else if (sourceIds.contains(node.id())) "source"
    else
      node match {
        case _: ControlStructure                                => "guard"
        case _: MethodParameterIn                               => "param"
        case _: MethodReturn                                    => "return"
        case call: Call if isContentField(call)                 => "field"
        case call: Call if call.name == "<operator>.assignment" => "assign"
        case call: Call if !call.name.startsWith("<operator>.") => "call"
        case _                                                  => "data"
      }

  private def significant(node: CfgNode, sourceIds: Set[Long], sinkId: Long): Boolean =
    node.id() == sinkId || sourceIds.contains(node.id()) || (node match {
      case _: ControlStructure  => true
      case _: MethodParameterIn => true
      case call: Call =>
        !noise(call.code) && (
          isContentField(call) ||
            !call.name.startsWith("<operator>.") ||
            call.name == "<operator>.assignment" ||
            call.name.contains("concat")
        )
      case _: MethodReturn => true
      case _               => false
    })

  private def edgeKind(segment: List[CfgNode], to: CfgNode): String = {
    def isField(node: CfgNode): Boolean = node match {
      case call: Call => isContentField(call)
      case _          => false
    }
    if (to.isInstanceOf[ControlStructure]) "control"
    else if (to.isInstanceOf[MethodParameterIn]) "call-arg"
    else if (segment.exists(_.isInstanceOf[MethodReturn])) "return"
    else if (isField(to) || segment.exists(isField)) "field"
    else "data"
  }

  def build(paths: List[TaintPath], sources: Set[CfgNode]): List[SinkGraph] = {
    val sourceIds = sources.map(_.id())
    val paramPatterns = List(
      """get_query_var\(\s*["']([^"']+)["']""".r,
      """\$_GET\[\s*["']([^"']+)["']""".r,
      """\$_POST\[\s*["']([^"']+)["']""".r,
      """\$_REQUEST\[\s*["']([^"']+)["']""".r
    )
    def paramOf(code: String): Option[String] =
      paramPatterns.view.flatMap(pattern => pattern.findFirstMatchIn(code)).headOption.map(_.group(1))

    paths
      .groupBy(_.sink.id())
      .values
      .toList
      .map { group =>
        val sink  = group.head.sink
        val ids   = scala.collection.mutable.Map.empty[(String, Int, String), String]
        val order = scala.collection.mutable.ListBuffer.empty[(String, Int, String)]
        val byKey = scala.collection.mutable.Map.empty[(String, Int, String), CfgNode]
        def keyOf(node: CfgNode): (String, Int, String) = (fileOf(node), lineOf(node), node.code)
        def idOf(node: CfgNode): String = {
          val key = keyOf(node)
          ids.getOrElseUpdate(
            key, {
              order += key
              byKey.getOrElseUpdate(key, node)
              s"n${ids.size + 1}"
            }
          )
        }

        val edges = scala.collection.mutable.LinkedHashSet.empty[SinkGraphEdge]
        group.foreach { path =>
          val seenIds = scala.collection.mutable.Set.empty[Long]
          val significantNodes = path.path.zipWithIndex.filter { case (node, _) =>
            significant(node, sourceIds, sink.id()) && seenIds.add(node.id())
          }
          significantNodes.sliding(2).foreach {
            case List((a, ia), (b, ib)) =>
              val segment = if (ib > ia) path.path.slice(ia + 1, ib + 1) else List(b)
              val from    = idOf(a)
              val to      = idOf(b)
              if (from != to) edges += SinkGraphEdge(from, to, edgeKind(segment, b))
            case _ =>
          }
        }

        val nodes = order.toList.map { key =>
          val (file, line, code) = key
          val node               = byKey(key)
          SinkGraphNode(ids(key), s"$file:$line", code, nodeKind(node, sourceIds, sink.id()))
        }

        val sourceNodes = nodes.filter(_.kind == "source")
        val params      = sourceNodes.flatMap(node => paramOf(node.code)).distinct.sorted
        SinkGraph(
          kind = group.head.kind,
          sink = s"${atOf(sink)}  ${sink.code}",
          params = params,
          sources = sourceNodes.map(_.id),
          guards = nodes.filter(_.kind == "guard").map(_.id),
          nodes = nodes,
          edges = edges.toList
        )
      }
      .sortBy(graph => graph.sink)
  }

}
