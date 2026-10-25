package bee.zipper.cli.scan.cmd

import bee.zipper.cli.scan.EngineConfig
import bee.zipper.core.Api
import bee.zipper.core.analysis.aliasing.DefaultAliasAnalysis
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.analysis.taint.{DefaultTaintAnalysis, PathChainMerger, TaintPath}
import bee.zipper.util.sys.FileSys
import io.circe.generic.auto.*
import io.circe.parser.parse
import io.shiftleft.codepropertygraph.generated.Cpg
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
case class NaviChainSpec(name: String, segments: List[NaviSegmentSpec], join: Option[Boolean] = None)

case class NaviConfig(chains: List[NaviChainSpec])

object NaviConfig {
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

  def run(config: NaviConfig, cpg: Cpg, api: Api, c: EngineConfig, outputDir: String): Unit = {
    val sourceSearcher = TaintSourceSearcher.create(
      cpg,
      api.vfg,
      enableWrapperFinder = false,
      enableIndirectSuperGlobalFetching = c.enableIndirectSuperGlobalFetching
    )
    val (allSources, _) = sourceSearcher.search()
    val sqlSources      = sourceSearcher.sqlQuerySources()
    val sqlSourceIds    = sqlSources.map(_.id()).toSet
    val defaultSources  = allSources.filterNot(source => sqlSourceIds.contains(source.id()))
    val allSinks        = TaintSinkSearcher.create(cpg, api.vsa).search()

    logger.info(
      s"navi: default sources=${defaultSources.size}, sql sources=${sqlSources.size}, sink kinds=${allSinks.keys.toList.sorted
          .mkString(",")}"
    )

    def resolveSources(selector: String): List[CfgNode] =
      selector.trim.toLowerCase match {
        case "default"                                   => defaultSources
        case "sql" | "sqlquery" | "sqlread" | "sql-read" => sqlSources
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

    def resolveSinks(selector: String): Map[String, List[TaintSink]] =
      selector.trim.toLowerCase match {
        case "sqlread" | "sql-read"   => sqlSinks(SqlStatementKind.Read)
        case "sqlwrite" | "sql-write" => sqlSinks(SqlStatementKind.Write)
        case "sql" | "sqlquery"       => allSinks.filter { case (sinkKind, _) => sinkKind.toLowerCase.contains("sql") }
        case other                    => allSinks.filter { case (sinkKind, _) => sinkKind.equalsIgnoreCase(other) }
      }

    config.chains.foreach { chain =>
      val chainDir = Paths.get(outputDir, "navi", sanitize(chain.name))
      FileSys.ensureDirectoryExists(chainDir.toString)
      val perSegment = chain.segments.zipWithIndex.map { case (segment, index) =>
        val sources   = resolveSources(segment.source)
        val sinks     = resolveSinks(segment.sink)
        val sinkCount = sinks.values.map(_.size).sum
        val paths =
          if (sources.isEmpty || sinkCount == 0) {
            logger.warn(
              s"navi[${chain.name}] segment ${index + 1}: empty sources or sinks (sources=${sources.size}, sinks=$sinkCount)"
            )
            List.empty[TaintPath]
          } else analyzeSegment(cpg, sources, sinks, api, c)
        val label = segment.name.getOrElse(s"segment-${index + 1}")
        writeReport(paths, chainDir.resolve(s"${index + 1}-$label").toString)
        logger.info(s"navi[${chain.name}] ${segment.source} -> ${segment.sink}: ${paths.size} paths")
        paths
      }
      if (chain.join.contains(true) && perSegment.size > 1) {
        val joined = perSegment.reduceLeft(joinPaths)
        writeReport(joined, chainDir.resolve("joined").toString)
        logger.info(s"navi[${chain.name}] joined: ${joined.size} paths")
      }
    }
  }

  private def analyzeSegment(
    cpg: Cpg,
    sources: List[CfgNode],
    sinks: Map[String, List[TaintSink]],
    api: Api,
    c: EngineConfig
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
      enableControlStructure = c.enableControlStructure,
      enableImplicitTaint = c.enableImplicitTaint
    )
    val result = analysis.analyze().paths.toList
    logger.info(s"navi segment: sources=${sources.size}, sinkKinds=${sinks
        .map { case (k, v) => s"$k:${v.size}" }}, paths=${result.size}, multi=${result.count(_.path.size > 1)}")
    result
  }

  /** Concatenates paths whose shared intermediate node matches (same node id, or same file/line/code). */
  private def joinPaths(left: List[TaintPath], right: List[TaintPath]): List[TaintPath] = {
    val byHead: Map[Any, List[TaintPath]] = right
      .flatMap(path => List((path.path.head.id(): Any, path), (nodeKey(path.path.head): Any, path)))
      .groupBy(_._1)
      .view
      .mapValues(_.map(_._2).distinct)
      .toMap

    val joined = left.flatMap { prefix =>
      val last  = prefix.path.last
      val tails = byHead.getOrElse(last.id(), Nil) ++ byHead.getOrElse(nodeKey(last), Nil)
      tails.map(tail => TaintPath(prefix.kind, order = true, prefix.path ++ tail.path.drop(1)))
    }

    joined.groupBy(path => (path.path.head.id(), path.path.last.id(), path.path.size)).values.map(_.head).toList
  }

  private def nodeKey(node: CfgNode): (String, Int, String) =
    (node.file.headOption.map(_.name).getOrElse(""), node.lineNumber.getOrElse(-1), node.code)

  private def writeReport(paths: List[TaintPath], dir: String): Unit = {
    FileSys.ensureDirectoryExists(dir)
    val clusters = PathChainMerger.merge(paths).map(group => TaintResult.constructCluster(group, Set.empty))
    val summary  = TaintResult.AnalysisSummary(clusters.size, paths.size, clusters)
    val stream   = new PrintStream(new FileOutputStream(Paths.get(dir, "taint-analysis-result.json").toFile))
    try stream.println(TaintResult.renderSummary(summary))
    finally stream.close()
  }

  private def sanitize(name: String): String =
    name.map(ch => if (ch.isLetterOrDigit || ch == '-' || ch == '_') ch else '-').mkString
}
