package bee.zipper.cli.scan.cmd

import bee.zipper.cli.scan.EngineConfig
import bee.zipper.core.Api
import bee.zipper.core.analysis.aliasing.DefaultAliasAnalysis
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.core.analysis.taint.{
  CompactFlowBuilder,
  DefaultTaintAnalysis,
  PathChainMerger,
  PathFeasibility,
  BranchTrimming,
  SinkGraphBuilder,
  SqlProbeSelector,
  TaintPath,
  TaintSliceBuilder
}
import bee.zipper.util.sys.FileSys
import io.circe.generic.auto.*
import io.circe.parser.parse
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import java.io.{FileOutputStream, PrintStream}
import java.nio.file.{Files, Path, Paths}

/** One segment of a navigation chain: taint from `source` to `sink`.
  *
  * Selectors are resolved against the loaded source/sink specifications:
  *   - source: `default` (non-SQL sources), `sqlQuery`/`sqlRead` (database reads), `sql`/`sqlWrite`
  *   - sink: any vulnerability kind name (e.g. `Xss`), `sql`, `sqlRead`, `sqlWrite`
  */
case class NaviSegmentSpec(source: String, sink: String, name: Option[String] = None)

/** A chain is a sequence of segments. When `join` is enabled, paths of adjacent segments are concatenated at the
  * intermediate node shared by the sink of one segment and the source of the next one.
  */
case class NaviChainSpec(
  name: String,
  segments: List[NaviSegmentSpec],
  join: Option[Boolean] = None,
  bridge: Option[String] = None
)

case class NaviConfig(chains: List[NaviChainSpec])

object NaviConfig {

  /** The default navigation chains. They are fixed so that every run reports the same chain names.
    *
    * `xss-direct` request value echoed directly (reflected XSS) `xss-second-order` request value stored, read back,
    * echoed (stored XSS) `sqlwrite-direct` request value written into the database (injection) `read-to-write` database
    * value written back into the database `sqlread-direct` request value reaching a database read
    * `sqlwrite-second-order` request value stored, read back, written again
    */
  val defaultChains: List[NaviChainSpec] = List(
    NaviChainSpec("xss-direct", List(NaviSegmentSpec("default", "Xss"))),
    NaviChainSpec(
      "xss-second-order",
      List(NaviSegmentSpec("default", "sqlRead"), NaviSegmentSpec("sqlRead", "Xss")),
      join = Some(true)
    ),
    NaviChainSpec("sqlwrite-direct", List(NaviSegmentSpec("default", "sqlWrite"))),
    NaviChainSpec("read-to-write", List(NaviSegmentSpec("sqlRead", "sqlWrite"))),
    NaviChainSpec("sqlread-direct", List(NaviSegmentSpec("default", "sqlRead"))),
    NaviChainSpec(
      "sqlwrite-second-order",
      List(NaviSegmentSpec("default", "sqlRead"), NaviSegmentSpec("sqlRead", "sqlWrite")),
      join = Some(true)
    )
  )

  def default: NaviConfig = NaviConfig(defaultChains)

  def load(path: String): NaviConfig = {
    val content = Files.readString(Paths.get(path))
    val json    = parse(content).getOrElse(throw new RuntimeException(s"failed to parse navi config: $path"))
    json.as[NaviConfig].getOrElse(throw new RuntimeException(s"failed to decode navi config: $path"))
  }
}

/** Runs a navigation configuration: every chain segment is analyzed on its own and reported separately; chains with
  * `join = true` additionally produce a report where the segment paths are connected at shared intermediate nodes.
  */
object NaviAnalysis {

  private val logger = LoggerFactory.getLogger(this.getClass)

  /** `-Dzipper.navi.debug=true` prints the resolved source/sink nodes, to diagnose chain bridging. */
  private val debug = java.lang.Boolean.getBoolean("zipper.navi.debug")

  private def describe(node: CfgNode): String = {
    val location = node.file.headOption.map(_.name).getOrElse("?")
    s"$location:${node.lineNumber.getOrElse(-1)}  ${node.code.take(160).replace('\n', ' ')}"
  }

  /** Fields that carry displayed content: title, body, excerpt and comments. */
  private val wpContentFields: Set[String] = Set(
    "post_title",
    "post_content",
    "post_excerpt",
    "comment_content",
    "comment_author",
    "comment_author_email",
    "comment_author_url"
  )

  private val wpDbReadNames = Set("get_row", "get_results", "get_var", "get_col")

  /** Getters that return WordPress objects; the value is read from a database inside these implementations. */
  private val wpGetterClasses: Map[String, String] = Map(
    "get_post"     -> "wp_post",
    "get_comment"  -> "wp_comment",
    "get_term"     -> "wp_term",
    "get_userdata" -> "wp_user",
    "get_posts"    -> "wp_query",
    "get_comments" -> "wp_comment_query",
    "get_users"    -> "wp_user_query",
    "get_terms"    -> "wp_term_query"
  )

  private def wpObjectField(call: Call): Option[String] =
    if (call.name != Operators.fieldAccess) None
    else call.argumentOption(2).map(_.code).filter(wpContentFields.contains)

  private def enclosingClass(node: CfgNode): Option[String] =
    Option(node.method).flatMap(method => method.typeDecl.headOption).map(_.name.toLowerCase)

  /** The database access a content-field read consumes: either a concrete database call (file, line) or the class of
    * the getter that produced the object (`$post = get_post(...)` -> class-wp-post.php).
    */
  private def bridgeAnchor(fieldRead: Call): Option[Either[(String, Int), String]] = {
    val base = fieldRead.argumentOption(1).map(_.code)
    val line = fieldRead.lineNumber.getOrElse(-1)
    for {
      _          <- wpObjectField(fieldRead)
      baseCode   <- base
      assignment <- nearestAssignment(fieldRead, baseCode, line)
      source     <- assignment.argumentOption(2).collect { case call: Call => call }
      anchor <- source match {
        case call if wpDbReadNames.contains(call.name) =>
          Some(Left((call.file.name.headOption.getOrElse(""), call.lineNumber.getOrElse(-1))))
        case call if wpGetterClasses.contains(call.name) =>
          Some(Right(wpGetterClasses(call.name)))
        case _ => None
      }
    } yield anchor
  }

  private def nearestAssignment(node: CfgNode, target: String, line: Int): Option[Call] =
    Option(node.method).flatMap { method =>
      method.ast
        .collectAll[Call]
        .filter(_.isGenericAssignment)
        .filter(a => a.argumentOption(1).exists(_.code == target))
        .filter(a => line < 0 || a.lineNumber.forall(_ <= line))
        .toList
        .sortBy(a => a.lineNumber.getOrElse(Int.MinValue))
        .reverse
        .headOption
    }

  def run(
    config: NaviConfig,
    cpg: Cpg,
    api: Api,
    c: EngineConfig,
    outputDir: String,
    enableNaviControlFlow: Boolean = true
  ): Unit = {
    val sourceSearcher = TaintSourceSearcher.create(
      cpg,
      api.vfg,
      enableWrapperFinder = false,
      enableIndirectSuperGlobalFetching = c.enableIndirectSuperGlobalFetching
    )
    val allSources     = sourceSearcher.requestSources()
    val sqlSources     = sourceSearcher.sqlQuerySources()
    val defaultSources = allSources
    val wpObjectSources: List[CfgNode] =
      cpg.call.filter(call => wpObjectField(call).nonEmpty).toList
    val allSinks = TaintSinkSearcher.create(cpg, api.vsa).search()

    // "fileread" seam: calls that read a file's content. Used both as the sink of the
    // first segment and the source of the second one, so a write/upload stage can be
    // bridged with a later read stage (second order flows through the file system).
    val fileReadNames: Set[String] =
      Set(
        "fopen",
        "file_get_contents",
        "readfile",
        "fpassthru",
        "file",
        "fread",
        "stream_get_contents",
        "copyFileInStream"
      )
    val fileReadCalls: List[Call] = cpg.call.filter(call => fileReadNames.contains(call.name)).toList

    logger.info(
      s"navi: default sources=${defaultSources.size}, sql sources=${sqlSources.size}, sink kinds=${allSinks.keys.toList.sorted
          .mkString(",")}"
    )
    if (debug) {
      sqlSources.foreach(source => logger.info(s"[navi-debug] sql source: ${describe(source)}"))
      allSinks.toList.sortBy(_._1).foreach { case (kind, sinks) =>
        sinks.foreach {
          case CallArgumentSink(call, _) =>
            logger.info(s"[navi-debug] sink $kind: ${describe(call)}")
          case other => logger.info(s"[navi-debug] sink $kind: ${other.toString.take(160)}")
        }
      }
    }

    def resolveSources(selector: String): List[CfgNode] =
      selector.trim.toLowerCase match {
        case "default"                                   => defaultSources
        case "sql" | "sqlquery" | "sqlread" | "sql-read" => sqlSources
        case "wpobject" | "wp-object" | "wpobj"          => wpObjectSources
        case "fileread" | "file-read" | "file_read"      => fileReadCalls
        case other =>
          logger.warn(s"navi: unknown source selector '$other', using default sources")
          defaultSources
      }

    def sqlSinks(kind: SqlStatementKind): Map[String, List[TaintSink]] =
      allSinks
        .filter { case (sinkKind, _) => sinkKind.toLowerCase.contains("sql") }
        .view
        .mapValues(_.filter {
          case CallArgumentSink(call, _) => SqlStatementClassifier.kindOfCall(call).contains(kind)
          case _                         => false
        })
        .toMap

    /** `sqlRead` used as a sink means "a request value reached a database read". Those calls are exactly the SQL read
      * sources resolved for the next segment, so sinking on the same call nodes keeps the join key aligned: before
      * this, the selector reused the SQL-injection sink set (a handful of calls) and the second segment never linked.
      */
    def sqlReadSinks: Map[String, List[TaintSink]] = {
      val readCalls   = sqlSources.collect { case call: Call => call }
      val readCallIds = readCalls.map(_.id()).toSet
      val fromSources = readCalls.map(call => DirectNodeSink(call): TaintSink)
      val fromSinks = sqlSinks(SqlStatementKind.Read).values.flatten.toList.filter {
        case CallArgumentSink(call, _) => !readCallIds.contains(call.id())
        case _                         => true
      }
      val all = fromSources ++ fromSinks
      if (all.isEmpty) sqlSinks(SqlStatementKind.Read) else Map("SqlRead" -> all)
    }

    def resolveSinks(selector: String): Map[String, List[TaintSink]] =
      selector.trim.toLowerCase match {
        case "sqlread" | "sql-read"   => sqlReadSinks
        case "sqlwrite" | "sql-write" => sqlSinks(SqlStatementKind.Write)
        case "sql" | "sqlquery"       => allSinks.filter { case (sinkKind, _) => sinkKind.toLowerCase.contains("sql") }
        case "fileread" | "file-read" | "file_read" =>
          Map("FileRead" -> fileReadCalls.map(call => CallArgumentSink(call, call.argumentOption(1).toList)))
        case other => allSinks.filter { case (sinkKind, _) => sinkKind.equalsIgnoreCase(other) }
      }

    // Segment results are cached by (source, sink, control-flow mode). The default chains share segments
    // (e.g. `default -> sqlRead` is the first segment of both second-order chains), so every distinct segment is
    // analyzed once and reused instead of being recomputed per chain.
    val segmentCache = scala.collection.mutable.Map.empty[(String, String, Boolean), List[TaintPath]]

    def segmentPaths(segment: NaviSegmentSpec, controlFlow: Boolean): List[TaintPath] = {
      val key = (segment.source.trim.toLowerCase, segment.sink.trim.toLowerCase, controlFlow)
      segmentCache.getOrElseUpdate(
        key, {
          val sources   = resolveSources(segment.source)
          val sinks     = resolveSinks(segment.sink)
          val sinkCount = sinks.values.map(_.size).sum
          if (sources.isEmpty || sinkCount == 0) {
            logger.warn(
              s"navi segment ${segment.source} -> ${segment.sink}: empty sources or sinks (sources=${sources.size}, sinks=$sinkCount)"
            )
            List.empty[TaintPath]
          } else
            analyzeSegment(
              cpg,
              sources,
              sinks,
              api,
              c,
              enableControlStructure = controlFlow,
              includeUntaintedSinks = controlFlow
            )
        }
      )
    }

    config.chains.foreach { chain =>
      val chainDir = Paths.get(outputDir, "navi", sanitize(chain.name))
      FileSys.ensureDirectoryExists(chainDir.toString)
      val perSegment = chain.segments.zipWithIndex.map { case (segment, index) =>
        val controlFlow = enableNaviControlFlow && c.enableControlStructure && index < chain.segments.size - 1
        val sources     = resolveSources(segment.source)
        val paths       = segmentPaths(segment, controlFlow)
        if (c.enableNaviDebugDump) {
          val label = segment.name.getOrElse(s"segment-${index + 1}")
          writeReport(paths, chainDir.resolve(s"${index + 1}-$label").toString, sources)
        }
        logger.info(s"navi[${chain.name}] ${segment.source} -> ${segment.sink}: ${paths.size} paths")
        (paths, sources)
      }
      if (chain.join.contains(true) && perSegment.size > 1) {
        val bridgeWp = chain.bridge.exists(value => value.toLowerCase.contains("wp"))
        val joined   = perSegment.map(_._1).reduceLeft((left, right) => joinPaths(left, right, bridgeWp))
        // If an intermediate sink B is not reached by the previous segment (it is an empty sink there), a B -> C
        // chain from the next segment still belongs to the navigation and is added on its own. Empty sinks C (paths
        // that consist of the sink only) are never added.
        val extra =
          if (perSegment.size == 2) {
            val first        = perSegment.head._1
            val second       = perSegment(1)._1
            val realSinkIds  = first.filter(_.path.size > 1).map(_.sink.id()).toSet
            val realSinkLine = first.filter(_.path.size > 1).map(path => lineKey(path.sink)).toSet
            second.filter(path =>
              path.path.size > 1 &&
                !realSinkIds.contains(path.path.head.id()) &&
                !realSinkLine.contains(lineKey(path.path.head))
            )
          } else Nil
        val joinedAll = (joined ++ extra)
          .groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size))
          .values
          .map(_.head)
          .toList
          .map(PathFeasibility.keepConnected)
          .flatMap(BranchTrimming.trim)
        val joinedSources = perSegment
          .flatMap(_._2)
          .distinctBy(_.id())
          .filterNot {
            case call: Call => wpObjectField(call).nonEmpty
            case _          => false
          }
        logger.info(
          s"navi[${chain.name}] joined: ${joinedAll.size} paths (${joined.size} linked, ${extra.size} from empty intermediate sinks)"
        )
        writeGraphs(joinedAll, chainDir.toString, joinedSources)
        if (c.enableNaviDebugDump) writeReport(joinedAll, chainDir.resolve("joined").toString, joinedSources)
      } else {
        writeGraphs(perSegment.head._1, chainDir.toString, perSegment.head._2)
      }
    }
  }

  private def analyzeSegment(
    cpg: Cpg,
    sources: List[CfgNode],
    sinks: Map[String, List[TaintSink]],
    api: Api,
    c: EngineConfig,
    enableControlStructure: Boolean,
    includeUntaintedSinks: Boolean
  ): List[TaintPath] = {
    val aliasFinder =
      if (c.enableOnDemandAliasAnalysis && !c.enableObjectDataDependency)
        Some(DefaultAliasAnalysis(api.vsa, api.icfg()))
      else
        None
    val analysis = new DefaultTaintAnalysis(
      cpg,
      sources,
      sinks,
      api.vsa,
      strict = true,
      exploitMode = false,
      enableReachAnalysis = false,
      enableDeduplicateFlow = c.enableDeduplicateFlow,
      enableCustomSanitizer = c.enableCustomSanitizer,
      enableKeywordMatching = c.enableSanitizerKeywordMatching,
      aliasFinder = aliasFinder,
      enableControlStructure = enableControlStructure,
      enableImplicitTaint = enableControlStructure && c.enableImplicitTaint,
      includeUntaintedSinks = includeUntaintedSinks
    )
    val result = analysis.analyze().paths.toList
    logger.info(s"navi segment: sources=${sources.size}, sinkKinds=${sinks
        .map { case (k, v) => s"$k:${v.size}" }}, paths=${result.size}, multi=${result.count(_.path.size > 1)}")
    result
  }

  /** Concatenates paths whose shared intermediate node matches (same node id, or same file/line/code). */
  private def joinPaths(left: List[TaintPath], right: List[TaintPath], bridgeWp: Boolean = false): List[TaintPath] = {
    val byHead: Map[Any, List[TaintPath]] = right
      .flatMap(path =>
        List(
          (path.path.head.id(): Any, path),
          (nodeKey(path.path.head): Any, path),
          (lineKey(path.path.head): Any, path)
        )
      )
      .groupBy(_._1)
      .view
      .mapValues(_.map(_._2).distinct)
      .toMap

    val joined = left.flatMap { prefix =>
      val last = prefix.path.last
      val tails =
        byHead.getOrElse(last.id(), Nil) ++
          byHead.getOrElse(nodeKey(last), Nil) ++
          // the same statement may end at the outer call (get_row) but start at the inner one (prepare)
          byHead.getOrElse(lineKey(last), Nil)
      tails.map(tail =>
        TaintPath(
          tail.kind,
          order = true,
          prefix.path ++ tail.path.drop(1),
          Some(tail.sink),
          middleNode = Some(tail.path.head),
          dataflowNodes = prefix.dataflowNodes ++ tail.dataflowNodes,
          optionalGuards = (prefix.optionalGuards ++ tail.optionalGuards).distinct
        )
      )
    }

    // WordPress bridge: a database row is copied into an object field dynamically (`$this->$key = $value`), so the
    // field-sensitive dataflow cannot connect the getter result with the field read. Join a path ending at a
    // database read of class family F with a path starting at a WP object field read of the same family.
    val bridged =
      if (!bridgeWp) Nil
      else {
        right.flatMap { suffix =>
          suffix.path.head match {
            case call: Call =>
              bridgeAnchor(call) match {
                case Some(Left((file, line))) =>
                  val candidates = left.filter(prefix =>
                    prefix.path.last.file.headOption.getOrElse("") == file &&
                      prefix.path.last.lineNumber.getOrElse(-1) == line
                  )
                  attachAll(candidates, suffix)
                case Some(Right(cls)) =>
                  val candidates = left.filter(prefix => enclosingClass(prefix.path.last).exists(_.contains(cls)))
                  attachAll(candidates, suffix)
                case None => Nil
              }
            case _ => Nil
          }
        }
      }

    if (bridgeWp && bridged.nonEmpty) logger.info(s"navi bridge: ${bridged.size} WordPress object-field bridges")
    (joined ++ bridged)
      .groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size))
      .values
      .map(_.head)
      .toList
  }

  /** Keep all legal sources: one path per distinct source, the shortest one, for the anchored database access. */
  private def attachAll(candidates: List[TaintPath], suffix: TaintPath): List[TaintPath] =
    candidates
      .groupBy(_.path.head.id())
      .values
      .map(_.minBy(_.path.size))
      .map(prefix =>
        TaintPath(
          suffix.kind,
          order = true,
          prefix.path ++ suffix.path,
          Some(suffix.sink),
          middleNode = Some(prefix.path.last),
          dataflowNodes = prefix.dataflowNodes ++ suffix.dataflowNodes,
          optionalGuards = (prefix.optionalGuards ++ suffix.optionalGuards).distinct
        )
      )
      .toList

  private def lineKey(node: CfgNode): (String, Int) =
    (node.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse(""), node.lineNumber.getOrElse(-1))

  private def nodeKey(node: CfgNode): (String, Int, String) =
    (node.file.headOption.map(_.name).getOrElse(""), node.lineNumber.getOrElse(-1), node.code)

  /** Writes the agent facing report: a single graph file per chain, directly in the chain directory. */
  private def writeGraphs(paths: List[TaintPath], dir: String, sources: List[CfgNode]): Unit = {
    FileSys.ensureDirectoryExists(dir)
    val graphs       = SinkGraphBuilder.build(paths, sources.toSet)
    val graphsStream = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-graphs.json").toFile))
    try graphsStream.println(TaintResult.renderGraphs(graphs))
    finally graphsStream.close()
  }

  private def writeReport(paths: List[TaintPath], dir: String, sources: List[CfgNode]): Unit = {
    FileSys.ensureDirectoryExists(dir)
    val clusters = PathChainMerger.merge(paths).map(group => TaintResult.constructCluster(group, Set.empty))
    val summary  = TaintResult.AnalysisSummary(clusters.size, paths.size, clusters)
    val stream   = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-result.json").toFile))
    try stream.println(TaintResult.renderSummary(summary))
    finally stream.close()

    val slices       = TaintSliceBuilder.build(paths, sources.toSet, Some(new SqlProbeSelector))
    val slicesStream = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-slices.json").toFile))
    try slicesStream.println(TaintResult.renderSlices(slices))
    finally slicesStream.close()

    val flows       = CompactFlowBuilder.build(paths, sources.toSet)
    val flowsStream = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-flows.json").toFile))
    try flowsStream.println(TaintResult.renderFlows(flows))
    finally flowsStream.close()

    val graphs       = SinkGraphBuilder.build(paths, sources.toSet)
    val graphsStream = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-graphs.json").toFile))
    try graphsStream.println(TaintResult.renderGraphs(graphs))
    finally graphsStream.close()
  }

  private def sanitize(name: String): String =
    name.map(ch => if (ch.isLetterOrDigit || ch == '-' || ch == '_') ch else '-').mkString
}
