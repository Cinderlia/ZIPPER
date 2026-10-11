package bee.zipper.cli.scan

import bee.zipper.core.Api
import bee.zipper.core.cpgcreation.CpgGenerator
import bee.zipper.core.cpgcreation.php.PhpCpgGenerator
import bee.zipper.core.cpgcreation.php.passes.*
import bee.zipper.core.cpgcreation.pysrc.PythonCpgGenerator
import org.slf4j.LoggerFactory
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages}

import java.io.File
import java.nio.file.Paths
import scala.jdk.CollectionConverters.*

object CpgGeneration {
  private val logger = LoggerFactory.getLogger(this.getClass)

  /** create a new CPG or load from an existing CPG
    */
  def importCpg(basicConfig: BasicConfig): Option[Cpg] = {
    val pc = basicConfig.projectConfig
    if (pc.isLoadingCpgMode) CpgGeneration.loadExistingCpg(pc.cpg)
    else {
      SupportedLanguages.validateStatic(pc.language) match {
        case Left(err) =>
          logger.warn(err)
          None
        case _ =>
          val cpgLocation =
            scala
              .Option(basicConfig.cpgLocation)
              .filter(_.nonEmpty)
              .getOrElse(Paths.get(basicConfig.outputDir, "cpg.bin").toString)
          CpgGeneration.createCpg(
            pc.path,
            pc.language,
            pc.excludeDirs.asScala.toSeq,
            pc.excludeFiles.asScala.toSeq,
            basicConfig.outputDir,
            cpgLocation
          )
      }
    }
  }

  private def createCpg(
    projectPath: String,
    language: String,
    excludeDirs: Seq[String],
    excludeFiles: Seq[String],
    outputDir: String,
    cpgLocation: String
  ): Option[Cpg] = {
    val generator = {
      val (path, loc, eDirs, eFiles) =
        (File(projectPath).getAbsolutePath, Some(cpgLocation), excludeDirs, excludeFiles)

      language match {
        case Languages.PHP       => new PhpCpgGenerator(path, loc, eDirs, eFiles)
        case Languages.PYTHONSRC => new PythonCpgGenerator(path, loc, eDirs, eFiles)
      }
    }
    generator.mkCpg
  }

  /** Load an existing CPG from file with logging */
  private def loadExistingCpg(cpgPath: String): Option[Cpg] = {
    val cpgFile = new File(cpgPath)

    if (!cpgFile.exists()) {
      logger.error(s"CPG file does not exist: $cpgPath")
      return None
    }

    logger.info(s"Loading existing CPG from: $cpgPath")
    CpgGenerator.loadCpg(cpgPath) match {
      case Some(cpg) =>
        logger.info("CPG loaded successfully")
        Some(cpg)
      case None =>
        logger.error(s"Failed to load CPG from $cpgPath")
        None
    }
  }

  def applyPHPPasses(cpg: Cpg, api: Api, c: EngineConfig): Unit = {
    PhpCpgGenerator.runDataFlowLayer(cpg)

    if (c.enableEnhancedDynamicCall) {
      logger.info("Enabling enhanced dynamic call resolution")
      IterativeDynamicCallLayer.run(
        cpg,
        api.vsa,
        enhanced = true,
        fixJoernCallGraph = c.fixJoernCallGraph,
        Some(c.iterations)
      )
    } else if (c.enableTCheckerDynamicCall) {
      logger.info("Enabling TChecker-style dynamic call resolution")
      IterativeDynamicCallLayer.run(
        cpg,
        api.vsa,
        enhanced = false,
        fixJoernCallGraph = c.fixJoernCallGraph,
        Some(c.iterations)
      )
    }

    if (c.enableGlobalDataDependency) {
      logger.info("Building global variable def-use chains")
      GlobalVariableFlowLayer.run(cpg, api.globalDefUse(lightweight = true))
    }

    if (c.enableObjectDataDependency && !c.enableOnDemandAliasAnalysis) {
      logger.info("Building memory object def-use chains")
      MemoryFlowLayer.run(cpg, api.memoryDefUse())
    }

    // WordPress specific passes
    if (c.enableWordPress) {
      logger.info("Enabling WordPress hook and option resolution")
      WordPressHookResolutionLayer.run(cpg, api.vsa)
      WordPressOptionResolutionLayer.run(cpg, api.vsa)
    }
  }
}
