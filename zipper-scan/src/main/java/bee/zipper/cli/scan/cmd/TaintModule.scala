package bee.zipper.cli.scan.cmd

import bee.zipper.cli.scan.*
import bee.zipper.cli.scan.cmd.TaintCmd.*
import bee.zipper.cli.scan.cmd.TaintResult.*
import bee.zipper.core.Api
import bee.zipper.core.analysis.aliasing.DefaultAliasAnalysis
import bee.zipper.core.analysis.taint.*
import bee.zipper.core.analysis.taint.sourcesink.TaintSourceSearcher
import bee.zipper.core.cpgcreation.php.tagger.*
import bee.zipper.core.vuln.{SanitizerManager, SourceSinkSpecManager}
import bee.zipper.util.sys.FileSys
import io.circe.*
import io.circe.generic.semiauto.*
import io.circe.syntax.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory
import picocli.CommandLine
import picocli.CommandLine.{Command, Mixin}

import java.io.{File, FileOutputStream, PrintStream}
import java.nio.file.Paths
import scala.jdk.CollectionConverters.*

@Command(description = Array("Static taint analysis for PHP"))
class TaintModule extends AppModule {
  override def name: String = "taint"

  private val logger = LoggerFactory.getLogger(this.getClass)

  private def secondOrderConfig(finalSink: String): NaviConfig = NaviConfig(
    List(
      NaviChainSpec(
        name = if (finalSink.equalsIgnoreCase("Xss")) "second-order-xss" else "second-order-sql",
        segments = List(
          NaviSegmentSpec(source = "default", sink = "sqlRead", name = Some("request-to-sql-read")),
          NaviSegmentSpec(source = "sqlRead", sink = finalSink, name = Some("sql-read-to-final-sink"))
        ),
        join = Some(true)
      )
    )
  )

  private def oneSegmentConfig(name: String, source: String, sink: String): NaviConfig = NaviConfig(
    List(NaviChainSpec(name, List(NaviSegmentSpec(source, sink)), join = Some(false)))
  )

  @Mixin
  private val basicConfig = new BasicConfig

  override def run(): Unit = {
    // bound the rendering of cyclic symbolic structures such as self-referencing arrays
    System.setProperty("zipper.symbolic.print.depth", basicConfig.engineConfig.symbolicPrintDepth.toString)
    System.setProperty("zipper.source.root", basicConfig.projectConfig.path)
    System.setProperty("zipper.taint.sharedTable", basicConfig.engineConfig.enableSharedResultTable.toString)
    System.setProperty("zipper.taint.narrowUnresolved", basicConfig.engineConfig.enableNarrowUnresolvedCalls.toString)
    val outputDir = basicConfig.outputDir
    val reachabilityReport = ReachabilityReportMode
      .parse(basicConfig.engineConfig.enableReachabilityReport)
      .map(new ReachabilityReportCollector(_))
    FileSys.ensureDirectoryExists(outputDir)
    // Load custom configurations if provided
    loadCustomConfigurations()
    // Apply vuln kind filtering if provided
    applyVulnKindFilter()
    CpgGeneration.importCpg(basicConfig) match {
      case Some(cpg) =>
        if (basicConfig.engineConfig.enableServiceLocatorType) {
          new bee.zipper.core.cpgcreation.php.passes.ServiceLocatorTypePass(cpg).createAndApply()
        }
        if (basicConfig.engineConfig.enableIncludeScope && basicConfig.projectConfig.isLoadingCpgMode) {
          new bee.zipper.core.cpgcreation.php.passes.PhpIncludeScopePass(cpg).createAndApply()
        }
        val projectConfig = basicConfig.projectConfig
        val api           = Api.create(cpg, basicConfig.engineConfig.enhancedValueSetAnalysis)
        // Only apply PHP passes when creating a new CPG
        if (!basicConfig.projectConfig.isLoadingCpgMode) {
          CpgGeneration.applyPHPPasses(cpg, api, basicConfig.engineConfig)
        }
        if (basicConfig.engineConfig.enableNarrowUnresolvedCalls) {
          logger.info("Narrowing unresolved calls to argument-to-result flows")
          new bee.zipper.core.cpgcreation.php.passes.UnresolvedCallFlowPass(cpg).createAndApply()
        }
        val scenarioOption = basicConfig.engineConfig.scanScenarios != null
        val scenarios =
          if (scenarioOption) {
            basicConfig.engineConfig.enableControlStructure = true
            val selected = basicConfig.engineConfig.scanScenarios.asScala.toList
              .map(_.trim.toLowerCase)
              .filter(_.nonEmpty)
              .distinct
            if (selected.isEmpty)
              List("once-xss", "once-sql", "second-xss", "second-sql", "second-injection")
            else selected
          } else Nil
        val validScenarios   = Set("once-xss", "once-sql", "second-xss", "second-sql", "second-injection")
        val unknownScenarios = scenarios.toSet -- validScenarios
        require(unknownScenarios.isEmpty, s"Unknown --scan-scenarios: ${unknownScenarios.toList.sorted.mkString(",")}")
        require(scenarios.nonEmpty, "--scan-scenarios must select at least one scenario")
        val customNaviPath = basicConfig.engineConfig.customNaviConfig
        val requestedKinds = basicConfig.engineConfig.enabledVulnKinds.asScala.toSet
        scenarios.foreach { scenario =>
          val scenarioDir = Paths.get(outputDir, "scenarios", scenario).toString
          FileSys.ensureDirectoryExists(scenarioDir)
          val vulnKinds = scenario match {
            case "once-xss" | "second-xss" => Set("Xss")
            case _                         => Set("SQL", "SqlInjection")
          }
          val activeKinds = if (requestedKinds.nonEmpty) vulnKinds.intersect(requestedKinds) else vulnKinds
          require(activeKinds.nonEmpty, s"--vulnkind excludes all sinks for scenario '$scenario'")
          SourceSinkSpecManager.setActiveVulnKinds(activeKinds)
          SanitizerManager.setActiveVulnKinds(activeKinds)
          logger.info(s"Running scan scenario '$scenario' into $scenarioDir")
          try {
            scenario match {
              case "once-xss" | "once-sql" =>
                val result = executeStaticTaintAnalysis(
                  basicConfig.engineConfig,
                  cpg,
                  api,
                  reachabilityReport,
                  directDataflowOnly = true,
                  excludeDbMediatedFlows = true
                )
                generateReport(result, scenarioDir, true, reachabilityReport)
              case "second-xss" | "second-sql" =>
                val config =
                  if (customNaviPath != null && customNaviPath.nonEmpty) {
                    val loaded = NaviConfig.load(customNaviPath)
                    NaviConfig(loaded.chains.map { chain =>
                      val ending = if (scenario == "second-xss") "Xss" else "sql"
                      chain.copy(segments = chain.segments.dropRight(1) :+ chain.segments.last.copy(sink = ending))
                    })
                  } else secondOrderConfig(if (scenario == "second-xss") "Xss" else "sql")
                NaviAnalysis.run(config, cpg, api, basicConfig.engineConfig, scenarioDir, enableNaviControlFlow = true)
              case "second-injection" =>
                val config =
                  if (customNaviPath != null && customNaviPath.nonEmpty) {
                    val loaded = NaviConfig.load(customNaviPath)
                    NaviConfig(
                      loaded.chains.map(chain =>
                        chain
                          .copy(segments = chain.segments.dropRight(1) :+ chain.segments.last.copy(sink = "sqlWrite"))
                      )
                    )
                  } else oneSegmentConfig("request-to-sql-write", "default", "sqlWrite")
                NaviAnalysis.run(config, cpg, api, basicConfig.engineConfig, scenarioDir, enableNaviControlFlow = false)
            }
          } finally {
            SourceSinkSpecManager.clearActiveVulnKinds()
            SanitizerManager.clearActiveVulnKinds()
          }
        }
        // save cpg to file
        try cpg.close()
        catch { case ex: Exception => logger.warn("Error while closing CPG", ex) }
      case None => logger.warn("CPG generation or loading failed")
    }
  }

  /** Load custom source, sink, and sanitizer configurations if provided
    */
  private def loadCustomConfigurations(): Unit = {
    import scala.jdk.CollectionConverters.*

    // Load custom source configurations
    val customSourcePaths = basicConfig.engineConfig.customSourceConfigs.asScala.toList
    if (customSourcePaths.nonEmpty) {
      logger.info(s"Loading custom source configurations from: ${customSourcePaths.mkString(", ")}")
      try {
        SourceSinkSpecManager.loadCustomSourceConfigs(customSourcePaths)
      } catch {
        case e: Exception =>
          logger.error(s"Failed to load custom source configurations", e)
          throw e
      }
    }

    // Load custom sink configurations
    val customSinkPaths = basicConfig.engineConfig.customSinkConfigs.asScala.toList
    if (customSinkPaths.nonEmpty) {
      logger.info(s"Loading custom sink configurations from: ${customSinkPaths.mkString(", ")}")
      try {
        SourceSinkSpecManager.loadCustomSinkConfigs(customSinkPaths)
      } catch {
        case e: Exception =>
          logger.error(s"Failed to load custom sink configurations", e)
          throw e
      }
    }

    // Load custom sanitizer configurations
    val customSanitizerPaths = basicConfig.engineConfig.customSanitizerConfigs.asScala.toList
    if (customSanitizerPaths.nonEmpty) {
      logger.info(s"Loading custom sanitizer configurations from: ${customSanitizerPaths.mkString(", ")}")
      try {
        SanitizerManager.loadCustomSanitizerConfigs(customSanitizerPaths)
      } catch {
        case e: Exception =>
          logger.error(s"Failed to load custom sanitizer configurations", e)
          throw e
      }
    }
  }

  /** Apply vulnerability kind filtering across managers if CLI option is provided */
  private def applyVulnKindFilter(): Unit = {
    import scala.jdk.CollectionConverters.*
    val kinds = basicConfig.engineConfig.enabledVulnKinds.asScala.toSet
    if (kinds.nonEmpty) {
      bee.zipper.core.vuln.SourceSinkSpecManager.setActiveVulnKinds(kinds)
      bee.zipper.core.vuln.SanitizerManager.setActiveVulnKinds(kinds)
      logger.info(s"Enabled vulnerability kinds: ${kinds.mkString(", ")}")
    } else {
      bee.zipper.core.vuln.SourceSinkSpecManager.clearActiveVulnKinds()
      bee.zipper.core.vuln.SanitizerManager.clearActiveVulnKinds()
    }
  }

}

/** Shared methods for taint analysis
  */
object TaintCmd {

  /** Run STATIC taint analysis
    */
  def executeStaticTaintAnalysis(
    c: EngineConfig,
    cpg: Cpg,
    api: Api,
    reachabilityReport: Option[ReachabilityReportCollector] = None,
    directDataflowOnly: Boolean = false,
    excludeDbMediatedFlows: Boolean = false
  ): TaintAnalysisResult = {
    val aliasFinder =
      if (c.enableOnDemandAliasAnalysis && !c.enableObjectDataDependency)
        Some(DefaultAliasAnalysis(api.vsa, api.icfg()))
      else
        None
    val taintAnalysis =
      if (c.enablePHPJoernTaintAnalysis)
        PHPJoernTaintAnalysis(cpg, api.vfg, api.vsa)
      else
        DefaultTaintAnalysis(
          cpg,
          api.vfg,
          api.vsa,
          exploitMode = false,
          enableReachAnalysis = false,
          enableDeduplicateFlow = c.enableDeduplicateFlow,
          enableCustomSanitizer = c.enableCustomSanitizer,
          enableKeywordMatching = c.enableSanitizerKeywordMatching,
          enableIndirectSuperGlobalFetching = c.enableIndirectSuperGlobalFetching,
          aliasFinder = aliasFinder,
          enableControlStructure = !directDataflowOnly && c.enableControlStructure,
          enableImplicitTaint = !directDataflowOnly && c.enableImplicitTaint,
          includeUntaintedSinks = !directDataflowOnly && c.enableControlStructure
        )
    val result = taintAnalysis.analyze()
    if (c.enableReachabilityAnalysis || reachabilityReport.nonEmpty) {
      val reachability = new ReachabilityAnalysis(api.vsa, reachabilityReport)
      result.copy(paths = result.paths.filter { path =>
        val reachable = reachability.isReachable(path.path, Some(path.kind))
        !c.enableReachabilityAnalysis || reachable
      })
    } else if (excludeDbMediatedFlows) {
      val paths = result.paths.filterNot(TaintPathFilters.isDatabaseMediatedRequestFlow).toList
      val sources = TaintSourceSearcher
        .create(cpg, api.vfg, enableIndirectSuperGlobalFetching = c.enableIndirectSuperGlobalFetching)
        .requestSources()
        .toSet
      result.copy(
        paths = paths.iterator,
        slices = TaintSliceBuilder.build(paths, sources, Some(new SqlProbeSelector)),
        flows = CompactFlowBuilder.build(paths, sources),
        graphs = SinkGraphBuilder.build(paths, sources)
      )
    } else result
  }

  /** Generates JSON and SARIF reports based on static taint analysis result
    */
  def generateReport(
    taintAnalysisResult: TaintAnalysisResult,
    outputDir: String,
    sarif: Boolean,
    reachabilityReport: Option[ReachabilityReportCollector] = None
  ): Unit = {
    val jsonFile   = Paths.get(outputDir, "taint-analysis-result.json").toFile
    val jsonStream = new PrintStream(new FileOutputStream(jsonFile))
    import scala.jdk.CollectionConverters.*
    var vulnCount = 0
    val taintPaths =
      taintAnalysisResult.paths
        .sideEffect(path =>
          vulnCount += 1
          println(s"$vulnCount ${path.head.code}")
        )
        .toList

    reachabilityReport.foreach(_.writeReports(outputDir))

    val newDataflowEdges = taintAnalysisResult.newDataflowEdges.asScala.map(x => (x._1.code, x._2.code)).toSet
    val clusters =
      PathChainMerger.merge(taintPaths).map(paths => constructCluster(paths, newDataflowEdges))
    val summary = AnalysisSummary(clusters.size, vulnCount, clusters)
    jsonStream.println(renderSummary(summary))
    jsonStream.flush()
    jsonStream.close()

    // sink-centric slices: one entry per sink, with the union of its sources and statements
    val slicesFile   = Paths.get(outputDir, "taint-analysis-slices.json").toFile
    val slicesStream = new PrintStream(new FileOutputStream(slicesFile))
    try slicesStream.println(renderSlices(taintAnalysisResult.slices))
    finally slicesStream.close()

    val flowsFile   = Paths.get(outputDir, "taint-analysis-flows.json").toFile
    val flowsStream = new PrintStream(new FileOutputStream(flowsFile))
    try flowsStream.println(renderFlows(taintAnalysisResult.flows))
    finally flowsStream.close()

    val graphsFile   = Paths.get(outputDir, "taint-analysis-graphs.json").toFile
    val graphsStream = new PrintStream(new FileOutputStream(graphsFile))
    try graphsStream.println(renderGraphs(taintAnalysisResult.graphs))
    finally graphsStream.close()

    if (sarif) {
      val report   = SarifGenerator.reportForTaintPaths("taint-analysis", taintPaths)
      val jsonFile = Paths.get(outputDir, "taint-analysis-result.sarif").toFile
      SarifGenerator.writeReport(jsonFile.toPath, report)
    }
  }
}

/** Data model and utilities for representing and serializing the results of taint analysis
  */
object TaintResult {
  case class PathElement(file: String, line: Int, code: String) {
    override def toString: String = s"$file:$line $code"
  }

  case class Vulnerability(
    id: Int,
    kind: String,
    source: String,
    sink: String,
    features: Seq[String],
    hash: String,
    path: Seq[PathElement]
  )

  case class Cluster(
    sink: String,
    kind: String,
    vulnSize: Int,
    features: Seq[String],
    hash: String,
    vulns: Seq[Vulnerability]
  )

  case class AnalysisSummary(clusterSize: Int, allVulns: Int, clusters: Seq[Cluster])

  implicit val pathElementEncoder: Encoder[PathElement]     = deriveEncoder
  implicit val vulnerabilityEncoder: Encoder[Vulnerability] = deriveEncoder
  implicit val clusterEncoder: Encoder[Cluster]             = deriveEncoder
  implicit val summaryEncoder: Encoder[AnalysisSummary]     = deriveEncoder

  implicit val sqlProbeCandidateEncoder: Encoder[SqlProbeCandidate] = deriveEncoder
  implicit val sqlProbeEncoder: Encoder[SqlProbe]                   = deriveEncoder
  implicit val sliceSourceEncoder: Encoder[SliceSource]             = deriveEncoder
  implicit val sliceNodeEncoder: Encoder[SliceNode]                 = deriveEncoder
  implicit val taintSliceEncoder: Encoder[TaintSlice]               = deriveEncoder

  case class SliceSummary(sliceSize: Int, slices: Seq[TaintSlice])
  implicit val sliceSummaryEncoder: Encoder[SliceSummary] = deriveEncoder

  implicit val compactFlowEncoder: Encoder[CompactFlow] = deriveEncoder
  case class FlowSummary(flowSize: Int, flows: Seq[CompactFlow])
  implicit val flowSummaryEncoder: Encoder[FlowSummary] = deriveEncoder

  implicit val graphNodeEncoder: Encoder[SinkGraphNode] = deriveEncoder
  implicit val graphEdgeEncoder: Encoder[SinkGraphEdge] = deriveEncoder
  implicit val sinkGraphEncoder: Encoder[SinkGraph]     = deriveEncoder
  case class GraphSummary(sinkSize: Int, sinks: Seq[SinkGraph])
  implicit val graphSummaryEncoder: Encoder[GraphSummary] = deriveEncoder

  def constructCluster(paths: List[TaintPath], newEdges: Set[(String, String)]): Cluster = {
    import org.apache.commons.codec.digest.DigestUtils

    def buildVulnerability(id: Int, path: TaintPath): Vulnerability = {
      val elements = path.path.map { node =>
        PathElement(
          file = node.file.headOption.map(_.name.replace(File.separator, "/")).getOrElse(""),
          line = node.lineNumber.getOrElse(-1),
          code = node.code
        )
      }
      val features = TaintPathAnalyzer.extractFeatures(path, newEdges)
      val kind     = path.kind
      val source   = elements.head.toString
      val sink     = elements.last.toString
      val hash     = DigestUtils.md5Hex(s"$sink:$kind")
      Vulnerability(id, kind, source, sink, features, hash, elements)
    }

    val vulns = paths.zipWithIndex.map { case (p, id) => buildVulnerability(id, p) }
    val sink  = vulns.head.sink
    val kind  = vulns.head.kind
    val unresolved = paths.exists(path =>
      path.path.exists(node => bee.zipper.core.cpgcreation.php.passes.UnresolvedCallRegistry.contains(node.id()))
    )
    val features =
      (vulns.flatMap(_.features) ++ (if (unresolved) Seq("UnresolvedCall") else Nil)).distinct
    val hash = DigestUtils.md5Hex(s"$sink:$kind")

    Cluster(sink, kind, vulns.size, features, hash, vulns)
  }

  def renderSummary(summary: AnalysisSummary): String = Printer.spaces4.print(summary.asJson)

  def renderSlices(slices: List[TaintSlice]): String =
    Printer.spaces4.print(SliceSummary(slices.size, slices).asJson)

  def renderFlows(flows: List[CompactFlow]): String =
    Printer.spaces4.print(FlowSummary(flows.size, flows).asJson)

  def renderGraphs(graphs: List[SinkGraph]): String =
    Printer.spaces4.print(GraphSummary(graphs.size, graphs).asJson)
}

private object TaintPathAnalyzer {
  def extractFeatures(taintPath: TaintPath, newDataflowEdges: Set[(String, String)]): List[String] = {
    val part1 = taintPath.path.flatMap(FeatureTagger.value)
    val part2 = taintPath.path
      .sliding(2)
      .find {
        case List(a, b) => newDataflowEdges.contains((a.code, b.code))
        case _          => false
      }
      .map(_ => List(PhpFeature.ObjectDataDependency))
      .getOrElse(List.empty)

    (part1 ++ part2).map(_.toString).distinct
  }
}
