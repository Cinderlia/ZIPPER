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
    NaviChainSpec("read-to-write", List(NaviSegmentSpec("sqlRead", "sqlWriteLoose"))),
    NaviChainSpec("sqlread-direct", List(NaviSegmentSpec("default", "sqlRead"))),
    NaviChainSpec(
      "sqlwrite-second-order",
      List(NaviSegmentSpec("default", "sqlRead"), NaviSegmentSpec("sqlRead", "sqlWriteLoose")),
      join = Some(true)
    )
  )

  /** Chains added when WordPress support is enabled: WordPress hands database rows to object properties and renders
    * those properties later, so a read and its output are connected through `wpObject` rather than through the SQL read
    * call itself.
    */
  def default: NaviConfig = NaviConfig(defaultChains)

  /** Built-in chain set. The set is the same in every mode: WordPress support changes how the segments of a chain are
    * bridged, not which chains are reported, so the report layout stays stable for downstream tools.
    */
  def default(wordpress: Boolean): NaviConfig = NaviConfig(defaultChains)

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
    // Table level joins are only meaningful for WordPress style storage; they are enabled by the engine flag and, for
    // WordPress runs, by default (the `wp-table-xss` chain asks for one through its bridge name as well).
    val enableTableJoin = c.enableTableJoin || c.enableWordPress
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

    /** Calls that can execute a statement, whatever their exact name: used by the second-order SQL chains, where the
      * write is an application level call such as `$db->exec($sql)` or `$link->query($sql)` whose statement is only
      * visible through a local variable.
      */
    /** Calls that execute a statement, whatever their receiver type: application level database wrappers
      * (`$db->query(...)`, `$db->exec($sql)`) are not typed `PDO`/`mysqli` in the CPG, so the name + statement
      * classification decides instead of the declared receiver type.
      */
    val sqlExecutorNames: Set[String] = Set(
      "query",
      "exec",
      "execute",
      "execsql",
      "prepare",
      "preparestatement",
      "bindparam",
      "bindvalue",
      "mysqli_query",
      "mysqli_real_query",
      "mysqli_multi_query",
      "mysqli_stmt_execute",
      "mysql_query",
      "pg_query",
      "pg_send_query",
      "sqlite_query",
      "sqlite_exec",
      "mssql_query",
      "sqlsrv_query",
      "odbc_exec",
      "db2_exec",
      "runquery",
      "sqlquery",
      "sqlstatement",
      "multi_query",
      "real_query",
      "unbufferedquery",
      "executequery"
    )

    /** SQL write sinks resolved by call name and statement kind. Used for every write selector: the strict
      * type-annotated sink list misses application level wrappers such as `$db->query(...)`, which is the usual shape
      * of an injection point in PHP applications.
      */
    def nameBasedSqlWriteSinks: Map[String, List[TaintSink]] = {
      val calls = cpg.call
        .filter(call =>
          sqlExecutorNames.contains(call.name.toLowerCase) ||
            isRowWriteHelper(call)
        )
        .filter(call =>
          isRowWriteHelper(call) ||
            SqlStatementClassifier.kindOfCall(call).contains(SqlStatementKind.Write)
        )
        .toList
      Map("SqlWrite" -> calls.map(call => CallArgumentSink(call, call.argument.toList): TaintSink))
    }

    /** Row-level write helpers of application database layers (`$wpdb->insert/update/delete/replace`) carry the SQL
      * statement in a generated form and therefore never expose SQL text to `SqlStatementClassifier`; recognise them by
      * receiver and method name instead.
      */
    def isRowWriteHelper(call: Call): Boolean = {
      val name          = call.name.toLowerCase
      val rowHelpers    = Set("insert", "update", "delete", "replace", "insertmulti", "updatemulti")
      lazy val receiver = call.receiver.headOption.map(_.code.trim).getOrElse("")
      rowHelpers.contains(name) && (receiver == "$wpdb" || receiver.endsWith("->db") || receiver == "$db")
    }

    /** Write sinks for the second-order SQL chains: same resolution as `sqlWrite`, kept as a separate selector name so
      * olderchain configurations keep working.
      */
    def looseSqlWriteSinks: Map[String, List[TaintSink]] =
      nameBasedSqlWriteSinks.map { case (_, sinks) => ("SqlWriteLoose", sinks) }

    def resolveSinks(selector: String): Map[String, List[TaintSink]] =
      selector.trim.toLowerCase match {
        case "sqlread" | "sql-read"                           => sqlReadSinks
        case "sqlwriteloose" | "sql-write-loose" | "sqlloose" => looseSqlWriteSinks
        case "sqlwrite" | "sql-write"                         => nameBasedSqlWriteSinks
        case "sql" | "sqlquery" => allSinks.filter { case (sinkKind, _) => sinkKind.toLowerCase.contains("sql") }
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
        val bridge    = chain.bridge.map(_.toLowerCase).getOrElse("")
        val bridgeWp  = bridge.contains("wp")
        val bridgeTbl = bridge.contains("table") || enableTableJoin
        val joined =
          if (bridgeTbl && bridge.contains("table") && perSegment.size > 2)
            joinTableToWp(perSegment.head._1, perSegment(1)._1, perSegment(2)._1)
          else if (
            enableTableJoin && perSegment.size == 2 &&
            (chain.name == "xss-second-order" || chain.name == "sqlwrite-second-order")
          ) {
            // A row written by one request is read by another one, so the two segments share no node. Pair the writes
            // with the rows the second segment reads by table, and (for the output chain) keep the renderings.
            val nodeLevel  = joinPaths(perSegment.head._1, perSegment(1)._1, bridgeWp)
            val writePaths = segmentPaths(NaviSegmentSpec("default", "sqlWrite"), controlFlow = true)
            if (chain.name == "xss-second-order") {
              val renders = segmentPaths(NaviSegmentSpec("wpObject", "Xss"), controlFlow = false)
              nodeLevel ++ joinTableToWp(writePaths, perSegment.head._1, renders)
            } else {
              nodeLevel ++ joinPathsByTable(
                perSegment.head._1,
                writePaths,
                requireContentTable = true,
                requireContentColumn = true
              )
            }
          } else perSegment.map(_._1).reduceLeft((left, right) => joinPaths(left, right, bridgeWp))
        if (debug) logger.info(s"[navi-debug] ${chain.name}: join candidates=${joined.size} (bridge=$bridge)")
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
          .map { path =>
            // A table level join connects two paths across requests: the written row and the read row never share a
            // control-flow or dataflow edge, so connectivity is only checked for node level joins.
            if (bridge.contains("table")) path
            else PathFeasibility.keepConnected(path)
          }
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
    val bridged = if (!bridgeWp) Nil else bridgeWpPaths(left, right)

    if (bridgeWp && bridged.nonEmpty) logger.info(s"navi bridge: ${bridged.size} WordPress object-field bridges")
    (joined ++ bridged)
      .groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size))
      .values
      .map(_.head)
      .toList
  }

  /** WordPress tables whose rows are rendered back to the page; a table join is only reported for these. */
  private val contentTables = Set("posts", "postmeta", "comments", "commentmeta", "terms", "term_taxonomy")

  /** Bridges read paths to WP object-field read paths: the database row of class family F is copied into the object
    * that the suffix starts from. The end of a left path is its sink, not its last node (control flow enhancement may
    * append nodes after the sink).
    */
  private def bridgeWpPaths(left: List[TaintPath], right: List[TaintPath]): List[TaintPath] =
    right.flatMap { suffix =>
      suffix.path.head match {
        case call: Call =>
          bridgeAnchor(call) match {
            case Some(Left((file, line))) =>
              attachAll(left.filter(anchorMatches(file, line, _)), suffix)
            case Some(Right(cls)) =>
              attachAll(left.filter(prefix => enclosingClass(prefix.sink).exists(_.contains(cls))), suffix)
            case None => Nil
          }
        case _ => Nil
      }
    }

  private def anchorMatches(file: String, line: Int, path: TaintPath): Boolean = {
    val end = path.sink
    end.file.name.headOption.getOrElse("") == file && end.lineNumber.getOrElse(-1) == line
  }

  /** The row a page renders was usually read in the same file that renders it; requiring this keeps the table level
    * join from pairing every read of a table with every rendering of that family.
    */
  private def sameFile(render: TaintPath, base: TaintPath): Boolean = {
    val renderFile = render.path.head match {
      case call: Call => call.file.name.headOption
      case _          => None
    }
    renderFile.isDefined && renderFile == base.sink.file.name.headOption
  }

  private def anchorOf(call: Call): Option[Either[(String, Int), String]] = bridgeAnchor(call)

  /** Object family of a WordPress getter -> the tables a row of that family is read from. */
  private val wpClassTables: Map[String, Set[String]] = Map(
    "wp_post"              -> Set("posts", "postmeta"),
    "wp_comment"           -> Set("comments", "commentmeta"),
    "wp_user"              -> Set("users", "usermeta"),
    "wp_term"              -> Set("terms", "termmeta"),
    "wp_term_taxonomy"     -> Set("term_taxonomy", "term_relationships"),
    "wp_term_relationship" -> Set("term_relationships")
  )

  private def tablesOfClass(cls: String): Set[String] = {
    val base = cls.trim.stripPrefix("wp_")
    wpClassTables.getOrElse(cls.trim, Set(if (base.endsWith("s")) base else base + "s"))
  }

  /** Joins a written row, the read of the same content table and the rendering of that row through an object property.
    * The three stages happen in different requests, so the join is table level: a row written into `comments` is read
    * back from `comments` and rendered through a `wp_comment` field.
    */
  private def joinTableToWp(
    writes: List[TaintPath],
    reads: List[TaintPath],
    renders: List[TaintPath]
  ): List[TaintPath] = {
    val tableJoined = joinPathsByTable(writes, reads)
    logger.info(
      s"navi table join: writes=${writes.size}, reads=${reads.size}, written rows read back=${tableJoined.size}"
    )
    val joined = for {
      render <- renders
      call   <- render.path.head match { case call: Call => List(call); case _ => Nil }
      anchor <- anchorOf(call).toList
      base   <- tableJoined
      if anchor match {
        case Left((file, line)) => anchorMatches(file, line, base)
        case Right(cls) =>
          sqlTables(base.sink).exists(tablesOfClass(cls).contains) && sameFile(render, base)
      }
    } yield TaintPath(
      render.kind,
      order = true,
      base.path ++ render.path,
      Some(render.sink),
      middleNode = Some(base.sink),
      dataflowNodes = base.dataflowNodes ++ render.dataflowNodes,
      optionalGuards = (base.optionalGuards ++ render.optionalGuards).distinct
    )
    logger.info(s"navi table join: ${joined.size} written-row renderings")
    joined
      .groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size))
      .values
      .map(_.head)
      .toList
  }
  private val wpdbTablePattern =
    "(?i)\\$wpdb->(posts|postmeta|comments|commentmeta|users|usermeta|terms|term_taxonomy|term_relationships|options|links|termmeta|blogs|blogmeta)".r
  private val wpdbPrefixPattern = "(?i)\\$wpdb->prefix\\}?([a-z0-9_]+)".r

  private def nodeText(node: CfgNode): String = node match {
    case call: Call => (call.code :: call.argument.map(_.code).toList).mkString(" ")
    case other      => other.code
  }

  private def sqlTables(node: CfgNode): Set[String] = {
    val text     = nodeText(node)
    val named    = wpdbTablePattern.findAllMatchIn(text).map(_.group(1).toLowerCase).toSet
    val prefixed = wpdbPrefixPattern.findAllMatchIn(text).map(_.group(1).toLowerCase).toSet
    named ++ prefixed
  }

  private def sqlColumns(node: CfgNode, writeSide: Boolean): Set[String] = {
    val text   = nodeText(node)
    val select = "(?is)SELECT\\s+(.*?)\\s+FROM\\s".r.findAllMatchIn(text).flatMap(m => m.group(1).split(","))
    val insert = "(?is)INSERT\\s+(?:IGNORE\\s+)?INTO\\s+[^\\s(]+\\s*\\(([^)]*)\\)".r
      .findAllMatchIn(text)
      .flatMap(m => m.group(1).split(","))
    val update = "(?is)SET\\s+(.*?)(?:WHERE|$)".r
      .findAllMatchIn(text)
      .flatMap(m => m.group(1).split(",").flatMap(_.split("=").headOption))
    val columns = if (writeSide) insert ++ update else select
    columns
      .map(_.replace("`", "").trim.toLowerCase)
      .filter(column => column == "*" || column.matches("[a-z0-9_]+"))
      .toSet
  }

  /** Columns of the written row must be read back: a read of `*` carries every column, and when either side cannot be
    * parsed the table filter alone keeps the pair (the narrowing is the content-table restriction).
    */
  private def tableJoinCompatible(
    writeNode: CfgNode,
    readNode: CfgNode,
    shared: Set[String],
    requireContentTable: Boolean = true
  ): Boolean = {
    if (requireContentTable && !shared.exists(contentTables.contains)) false
    else if (shared.isEmpty) false
    else {
      val written = sqlColumns(writeNode, writeSide = true)
      val read    = sqlColumns(readNode, writeSide = false)
      // A rendering reads a column: when the read cannot be parsed there is no evidence that the written row is the one
      // that is displayed, so the pair is dropped.
      if (read.isEmpty) false
      else if (read.contains("*")) true
      else if (written.nonEmpty) written.intersect(read).nonEmpty
      else true
    }
  }

  /** Table level join: the row a request writes into table T is read back from the same table. This is the only way a
    * stored value and its rendering can meet when write and read happen in different requests and files.
    */
  /** Helpers that write a row from a column map instead of running SQL text. */
  private val rowWriteHelpers = Set("insert", "update", "delete", "replace", "insertmulti", "updatemulti")

  private def isRowWriteReceiver(receiver: String): Boolean =
    receiver == "$wpdb" || receiver == "$db" || receiver.endsWith("->db")

  /** Whether a path ends in a statement that writes rows. */
  private def isWriteCall(node: CfgNode): Boolean =
    node match {
      case call: Call =>
        SqlStatementClassifier.kindOfCall(call).contains(SqlStatementKind.Write) ||
        (rowWriteHelpers.contains(call.name.toLowerCase) &&
          call.receiver.headOption.map(_.code.trim).exists(isRowWriteReceiver))
      case _ => false
    }

  /** A write targets user-visible content when it names a content column, or when the write payload carries one of
    * those columns as an array key (`$wpdb->insert($wpdb->posts, array('post_content' => ...))`).
    */
  private def writesContentColumn(node: CfgNode): Boolean =
    sqlColumns(node, writeSide = true).exists(wpContentFields.contains) ||
      wpContentFields.exists(field => nodeText(node).contains(field))

  private def joinPathsByTable(
    left: List[TaintPath],
    right: List[TaintPath],
    requireContentTable: Boolean = true,
    requireContentColumn: Boolean = false
  ): List[TaintPath] = {
    val prefixes = left.map(path => (path, sqlTables(path.sink))).filter(_._2.nonEmpty)
    if (prefixes.isEmpty || right.isEmpty) Nil
    else {
      val joined = for {
        (prefix, prefixTables) <- prefixes
        suffix                 <- right
        suffixTables = sqlTables(suffix.sink)
        // Either side may be the one that writes: a read-to-write chain lists reads first, a write-to-read chain writes.
        prefixIsWrite = isWriteCall(prefix.sink)
        writeTables   = if (prefixIsWrite) prefixTables else suffixTables
        readTables    = if (prefixIsWrite) suffixTables else prefixTables
        writeNode     = if (prefixIsWrite) prefix.sink else suffix.sink
        readNode      = if (prefixIsWrite) suffix.sink else prefix.sink
        shared        = writeTables.intersect(readTables)
        contentColumn = !requireContentColumn || writesContentColumn(writeNode)
        if shared.nonEmpty && contentColumn &&
          tableJoinCompatible(writeNode, readNode, shared, requireContentTable)
      } yield TaintPath(
        suffix.kind,
        order = true,
        prefix.path ++ suffix.path,
        Some(suffix.sink),
        middleNode = Some(prefix.path.last),
        dataflowNodes = prefix.dataflowNodes ++ suffix.dataflowNodes,
        optionalGuards = (prefix.optionalGuards ++ suffix.optionalGuards).distinct
      )
      if (joined.nonEmpty) logger.info(s"navi table join: ${joined.size} write-to-read bridges")
      joined
        .groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size))
        .values
        .map(_.head)
        .toList
    }
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
