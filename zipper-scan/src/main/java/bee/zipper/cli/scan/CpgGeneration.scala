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

  private val FieldSummaryClass   = "class"
  private val FieldSummaryGlobals = "class+global"

  /** `--enable-field-summary` is a mode: bare flag means `class`, `class+global` also bridges `<global>` accesses. */
  private def fieldSummaryMode(value: String): Option[String] =
    Option(value).map(_.trim.toLowerCase).filter(_.nonEmpty).map {
      case FieldSummaryClass   => FieldSummaryClass
      case FieldSummaryGlobals => FieldSummaryGlobals
      case other =>
        throw new IllegalArgumentException(
          s"unknown --enable-field-summary mode '$other' (expected '$FieldSummaryClass' or '$FieldSummaryGlobals')"
        )
    }

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

    if (c.enableIncludeScope) {
      logger.info("Bridging include/require variable scopes")
      new PhpIncludeScopePass(cpg).createAndApply()
    }

    // A callable argument (`[$this, 'callback']`) is a value, not a call: without reconnecting it the callback body has no
    // incoming call edge and looks unreachable, although the value it returns is what the higher order call produces.
    if (c.enableCallbackFlow) {
      logger.info("Resolving callbacks passed to higher order PHP functions")
      new CallbackFlowPass(cpg).createAndApply()
    }

    // Twig templates are not part of the CPG, so a value printed through `|raw` has no sink. The pass only adds sink
    // nodes and a few data dependency edges, and is inert for projects that ship no Twig templates.
    if (c.enableTwigSinks) {
      logger.info("Bridging Twig template output sinks")
      new TwigRenderPass(cpg).createAndApply()
    }

    fieldSummaryMode(c.fieldSummary).foreach { mode =>
      logger.info(s"Bridging object field reads and writes ($mode)")
      new ClassFieldFlowPass(cpg, includeGlobal = mode == FieldSummaryGlobals).createAndApply()
    }

    if (c.enableGlobalDataDependency) {
      logger.info("Building global variable def-use chains")
      GlobalVariableFlowLayer.run(cpg, api.globalDefUse(lightweight = true))

      // Superglobals are shared by every file of the program, while the def-use chains above are ICFG based and can
      // only cross an already resolved call edge. Bridge the container entries (e.g. `$_SESSION['login']`) directly.
      logger.info("Bridging superglobal container reads and writes")
      new SuperglobalFlowPass(cpg, api.vsa).createAndApply()
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
