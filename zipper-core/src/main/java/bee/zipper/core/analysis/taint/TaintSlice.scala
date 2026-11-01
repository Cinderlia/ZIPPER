package bee.zipper.core.analysis.taint

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** A user input that flows into (or controls) a sink. */
case class SliceSource(file: String, line: Int, code: String, param: Option[String])

/** A statement of the slice around the sink (code is the complete source line). */
case class SliceNode(file: String, line: Int, code: String)

/** All inputs and statements that are relevant for one sink. */
case class TaintSlice(
  kind: String,
  sinkFile: String,
  sinkLine: Int,
  sinkCode: String,
  sqlProbe: Option[SqlProbe],
  sources: List[SliceSource],
  nodeCount: Int,
  nodes: List[SliceNode],
  pathCount: Int
)

/** Compact, LLM-oriented view of one sink reached from one source. */
case class CompactFlow(kind: String, sink: String, source: String, param: Option[String], steps: List[String])

/** Per-sink graph for symbolic execution: one node per source line and typed edges. */
case class SinkGraphNode(id: String, at: String, code: String)
case class SinkGraphEdge(from: String, to: String, kind: String)
case class SinkGraph(
  kind: String,
  sink: String,
  params: List[String],
  nodes: List[SinkGraphNode],
  edges: List[SinkGraphEdge]
)

/** Resolves the complete source line for a (file, line) pair. The project root is passed through the
  * `zipper.source.root` system property; lines are cached per file.
  */
object SourceCache {
  private val root = Option(System.getProperty("zipper.source.root"))
    .map(path => if (path.endsWith("/")) path else path + "/")
    .getOrElse("")
  private val files = mutable.Map.empty[String, Array[String]]

  private def linesOf(file: String): Array[String] =
    files.getOrElseUpdate(
      file, {
        try {
          val path = java.nio.file.Paths.get(root + file)
          if (java.nio.file.Files.exists(path))
            java.nio.file.Files.readAllLines(path).toArray(new Array[String](0))
          else Array.empty[String]
        } catch { case _: Throwable => Array.empty[String] }
      }
    )

  def codeAt(file: String, line: Int): Option[String] = {
    if (root.isEmpty || file.isEmpty || line <= 0) None
    else {
      val lines = linesOf(file)
      if (line <= lines.length) Some(lines(line - 1).trim) else None
    }
  }

  /** Complete statement starting at (file, line). A sink can span several lines (`printf(` ...), so following lines are
    * appended while brackets are unbalanced, up to a small limit.
    */
  def statementAt(file: String, line: Int): Option[String] = {
    if (root.isEmpty || file.isEmpty || line <= 0) None
    else {
      val lines = linesOf(file)
      if (line > lines.length) None
      else {
        val text   = new StringBuilder
        var depth  = 0
        var cursor = line
        var added  = 0
        var done   = false
        while (!done && cursor <= lines.length && added < 20) {
          val current = lines(cursor - 1)
          if (added > 0) text.append(' ')
          text.append(current.trim)
          depth += bracketBalance(current)
          added += 1
          val trimmed   = current.trim
          val endsBlock = trimmed.endsWith(";") || trimmed.endsWith("{") || trimmed.endsWith("}")
          val single    = depth <= 0 && added == 1 && !trimmed.endsWith("(") && !trimmed.endsWith(",")
          if (endsBlock || single) done = true
          cursor += 1
        }
        Some(text.toString)
      }
    }
  }

  private def bracketBalance(text: String): Int = {
    var depth = 0
    text.foreach {
      case '(' | '[' | '{' => depth += 1
      case ')' | ']' | '}' => depth -= 1
      case _               => ()
    }
    depth
  }
}

private[taint] object TaintSliceSupport {
  val paramPatterns = List(
    """get_query_var\(\s*["']([^"']+)["']""".r,
    """\$_GET\[\s*["']([^"']+)["']""".r,
    """\$_POST\[\s*["']([^"']+)["']""".r,
    """\$_REQUEST\[\s*["']([^"']+)["']""".r,
    """\$_COOKIE\[\s*["']([^"']+)["']""".r
  )

  def param(code: String): Option[String] =
    paramPatterns.view.flatMap(pattern => pattern.findFirstMatchIn(code)).headOption.map(_.group(1))

  def fileOf(node: CfgNode): String =
    node.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse("")

  def lineOf(node: CfgNode): Int = node.lineNumber.getOrElse(-1)

  def atOf(node: CfgNode): String = s"${fileOf(node)}:${lineOf(node)}"

  /** Complete source line when available, otherwise the node code. */
  def displayCode(node: CfgNode): String =
    SourceCache.statementAt(fileOf(node), lineOf(node)).getOrElse(node.code)

  /** One node per source line: different fragments of the same line collapse into the most representative node. */
  def perLine(nodes: List[CfgNode], sourceIds: Set[Long], sinkId: Long): List[CfgNode] =
    nodes
      .filterNot(node => node.isInstanceOf[Method] || node.isInstanceOf[TypeDecl])
      .groupBy(node => (fileOf(node), lineOf(node)))
      .values
      .map(candidates => candidates.minBy(node => (roleRank(node, sourceIds, sinkId), -node.code.length)))
      .toList
      .sortBy(node => (fileOf(node), lineOf(node)))

  def roleRank(node: CfgNode, sourceIds: Set[Long], sinkId: Long): Int =
    if (node.isInstanceOf[Method] || node.isInstanceOf[TypeDecl]) 99
    else if (node.id() == sinkId) 0
    else if (sourceIds.contains(node.id())) 1
    else
      node match {
        case _: ControlStructure                                => 2
        case _: MethodParameterIn                               => 3
        case call: Call if !call.name.startsWith("<operator>.") => 4
        case call: Call if call.name == "<operator>.assignment" => 5
        case _                                                  => 6
      }

  val contentFields = Set(
    "post_title",
    "post_content",
    "post_excerpt",
    "comment_content",
    "comment_author",
    "comment_author_email",
    "comment_author_url"
  )

  def isContentField(call: Call): Boolean =
    call.name == "<operator>.fieldAccess" && call.argumentOption(2).exists(arg => contentFields.contains(arg.code))

  def noise(code: String): Boolean = {
    val text = code.trim
    text.isEmpty || text == "RET" || text.startsWith("<unknown>") || text.startsWith("tmp")
  }
}

object TaintSliceBuilder {
  import TaintSliceSupport.*

  /** One slice per sink: complete source lines, one entry per line, and the paths' real sources. */
  def build(
    paths: List[TaintPath],
    sources: Set[CfgNode],
    probeSelector: Option[SqlProbeSelector] = None
  ): List[TaintSlice] = {
    val sourceIds = sources.map(_.id())
    paths
      .filter(_.path.size > 1)
      .map(_.trimmed)
      .groupBy(path => path.sink.id())
      .values
      .toList
      .map { group =>
        val sink     = group.head.sink
        val nodes    = perLine(group.flatMap(_.path), sourceIds, sink.id())
        val srcNodes = group.map(_.source).distinctBy(_.id())
        TaintSlice(
          kind = group.head.kind,
          sinkFile = fileOf(sink),
          sinkLine = lineOf(sink),
          sinkCode = displayCode(sink),
          sources = srcNodes.map(node => SliceSource(fileOf(node), lineOf(node), displayCode(node), param(node.code))),
          sqlProbe = probeSelector.flatMap(_.select(group)),
          nodeCount = nodes.size,
          nodes = nodes.map(node => SliceNode(fileOf(node), lineOf(node), displayCode(node))),
          pathCount = group.size
        )
      }
      .sortBy(slice => (slice.sinkFile, slice.sinkLine))
  }
}

object CompactFlowBuilder {
  import TaintSliceSupport.*

  private def significant(node: CfgNode, sourceIds: Set[Long], sinkId: Long): Boolean =
    node.id() == sinkId || sourceIds.contains(node.id()) || (node match {
      case _: Method            => false
      case _: TypeDecl          => false
      case _: ControlStructure  => true
      case _: MethodParameterIn => true
      case call: Call =>
        !noise(call.code) && (
          isContentField(call) ||
            !call.name.startsWith("<operator>.") ||
            call.name == "<operator>.assignment" ||
            call.name.contains("concat")
        )
      case _ => false
    })

  private def stepsOf(path: TaintPath, sourceIds: Set[Long]): List[String] = {
    val seen = mutable.Set.empty[Int]
    val out  = mutable.ListBuffer.empty[String]
    path.path.foreach { node =>
      if (significant(node, sourceIds, path.sink.id()) && !noise(node.code)) {
        val line = lineOf(node)
        if (seen.add(line)) out += s"${fileOf(node)}:$line  ${displayCode(node)}"
      }
    }
    out.toList
  }

  /** One flow per (sink, source): every input keeps its own dataflow. */
  def build(paths: List[TaintPath], sources: Set[CfgNode]): List[CompactFlow] = {
    val sourceIds = sources.map(_.id())
    paths
      .filter(_.path.size > 1)
      .map(_.trimmed)
      .groupBy(_.sink.id())
      .values
      .toList
      .flatMap { group =>
        val sink = group.head.sink
        group
          .map { path =>
            val source = path.source
            CompactFlow(
              kind = path.kind,
              sink = s"${atOf(sink)}  ${displayCode(sink)}",
              source = s"${atOf(source)}  ${displayCode(source)}",
              param = param(source.code),
              steps = stepsOf(path, sourceIds)
            )
          }
          .groupBy(flow => (flow.source, flow.param))
          .values
          .map(_.maxBy(_.steps.size))
          .toList
      }
      .sortBy(flow => (flow.sink, flow.source))
  }
}

object SinkGraphBuilder {
  import TaintSliceSupport.*

  private def significant(node: CfgNode, sourceIds: Set[Long], sinkId: Long): Boolean =
    node.id() == sinkId || sourceIds.contains(node.id()) || (node match {
      case _: Method            => false
      case _: TypeDecl          => false
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

  /** One graph per sink, nodes deduplicated by source line, edges from every execution deduplicated. */
  def build(paths: List[TaintPath], sources: Set[CfgNode]): List[SinkGraph] = {
    val sourceIds = sources.map(_.id())
    paths
      .filter(_.path.size > 1)
      .map(_.trimmed)
      .groupBy(_.sink.id())
      .values
      .toList
      .map { group =>
        val sink  = group.head.sink
        val ids   = mutable.Map.empty[(String, Int), String]
        val order = mutable.ListBuffer.empty[(String, Int)]
        val byKey = mutable.Map.empty[(String, Int), CfgNode]

        def keyOf(node: CfgNode): (String, Int) = (fileOf(node), lineOf(node))

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

        def representative(node: CfgNode): Unit = {
          val key = keyOf(node)
          byKey.get(key) match {
            case Some(existing) if roleRank(node, sourceIds, sink.id()) < roleRank(existing, sourceIds, sink.id()) =>
              byKey.update(key, node)
            case None => byKey.update(key, node)
            case _    =>
          }
        }

        val edges = mutable.LinkedHashSet.empty[SinkGraphEdge]
        group.foreach { path =>
          val seenIds = mutable.Set.empty[Long]
          val significantNodes = path.path.zipWithIndex.filter { case (node, _) =>
            significant(node, sourceIds, sink.id()) && seenIds.add(node.id())
          }
          significantNodes.foreach { case (node, _) => representative(node) }
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
          val (file, line) = key
          SinkGraphNode(ids(key), s"$file:$line", displayCode(byKey(key)))
        }
        val params = group.flatMap(path => param(path.source.code)).distinct.sorted
        SinkGraph(
          kind = group.head.kind,
          sink = s"${atOf(sink)}  ${displayCode(sink)}",
          params = params,
          nodes = nodes,
          edges = edges.toList
        )
      }
      .sortBy(graph => graph.sink)
  }
}
