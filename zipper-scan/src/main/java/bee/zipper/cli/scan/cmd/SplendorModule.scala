package bee.zipper.cli.scan.cmd

import bee.zipper.cli.scan.{AppModule, BasicConfig, CpgGeneration}
import bee.zipper.core.Api
import bee.zipper.core.analysis.model.database.{DatabaseSchema, StaticSchemaAnalysis}
import bee.zipper.core.analysis.taint.secondorder.TwoPhaseTaintAnalysis
import bee.zipper.core.analysis.taint.secondorder.splendor.*
import bee.zipper.core.analysis.taint.sourcesink.*
import bee.zipper.core.vuln.{SanitizerManager, SourceSinkSpecManager}
import bee.zipper.util.sys.FileSys
import io.circe.syntax.*
import org.slf4j.LoggerFactory
import picocli.CommandLine
import picocli.CommandLine.{Command, Mixin}

import java.io.{FileOutputStream, PrintStream}
import java.nio.file.Paths

@Command(description = Array("Toy implementation of Splendor"))
class SplendorModule extends AppModule {
  override def name: String = "splendor"

  private val logger = LoggerFactory.getLogger(this.getClass)

  @Mixin
  private val basicConfig = new BasicConfig

  override def run(): Unit = {
    val outputDir = basicConfig.outputDir
    FileSys.ensureDirectoryExists(outputDir)
    loadCustomConfigurations()
    applyVulnKindFilter()
    CpgGeneration.importCpg(basicConfig) match {
      case Some(cpg) =>
        implicit val api: Api = Api.create(cpg, basicConfig.engineConfig.enhancedValueSetAnalysis)

        // Only apply PHP passes when creating a new CPG
        if (!basicConfig.projectConfig.isLoadingCpgMode) {
          CpgGeneration.applyPHPPasses(cpg, api, basicConfig.engineConfig)
        }

        def buildSchema(): DatabaseSchema = {
          val analysis   = StaticSchemaAnalysis(cpg, api.vsa)
          val schema     = analysis.analyze()
          val jsonFile   = Paths.get(outputDir, "database-schema.json").toFile
          val jsonOutput = new PrintStream(new FileOutputStream(jsonFile))
          jsonOutput.println(schema.asJson)
          jsonOutput.close()
          schema
        }

        def runSplendor(schema: DatabaseSchema): Unit = {
          val sources = {
            val collector = TaintSourceSearcher.create(cpg, api.vfg)
            collector.search()._1
          }
          val kindToSinks = {
            val collector = TaintSinkSearcher.create(cpg, api.vsa)
            collector.search()
          }
          val sinks = kindToSinks.values.flatten.toList
          val anchors = {
            val detector = new AnchorDetector(cpg, sources, sinks)
            detector.detect()
          }
          println(anchors)
          val triples = {
            val recognizer = new TripleRecognizer(cpg, anchors, schema)
            recognizer.recognize()
          }
          println(triples.asJson)
          val taintAnalysis       = new TwoPhaseTaintAnalysis(cpg, triples, sources, kindToSinks, api.vsa)
          val taintAnalysisResult = taintAnalysis.analyze()
          TaintCmd.generateReport(taintAnalysisResult, outputDir, true)
        }

        val schema = buildSchema()
        runSplendor(schema)

        // Close CPG
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
