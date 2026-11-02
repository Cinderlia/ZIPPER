package bee.zipper.core.cpgcreation.php

import bee.zipper.core.Api
import bee.zipper.core.cpgcreation.CpgGenerator
import bee.zipper.core.cpgcreation.php.PhpCpgGenerator.*
import bee.zipper.core.cpgcreation.php.passes.*
import bee.zipper.core.cpgcreation.x.NormalizeCpgLayer
import bee.zipper.core.semantic.SemanticsGenerator
import bee.zipper.util.sys.FileSys
import io.joern.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.joern.dataflowengineoss.semanticsloader.Semantics
import io.joern.php2cpg.parser.PhpParser
import io.joern.php2cpg.{Php2Cpg, Config as Php2CpgConfig}
import io.joern.x2cpg.X2Cpg
import io.joern.x2cpg.frontendspecific.php2cpg.*
import io.joern.x2cpg.passes.frontend.{XTypeRecoveryConfig, XTypeStubsParserConfig}
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages}
import io.shiftleft.passes.CpgPassBase
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths}

class PhpCpgGenerator(
  val input: String,
  val output: Option[String] = None,
  excludeDirs: Seq[String] = Seq.empty,
  excludeFiles: Seq[String] = Seq.empty
) extends CpgGenerator {
  override def mkCpg: Option[Cpg] = {
    val config = Php2CpgConfig(phpParserBin = Some(parserBin))
    config.inputPath = input
    config.ignoredFiles = {
      val root  = Paths.get(input).toAbsolutePath.normalize
      val absOf = (p: String) => root.resolve(p).toAbsolutePath.toString
      // `--exclude-dirs=vendor` must also drop nested directories such as `tools/syndication/vendor`,
      // otherwise third-party code is still parsed and analyzed.
      PhpCpgGenerator.expandExcludedDirs(root, excludeDirs) ++ excludeFiles.map(absOf)
    }
    output match {
      case Some(value) => config.outputPath = value
      case None        =>
    }
    val php2Cpg = new Php2Cpg()
    val opt     = php2Cpg.createCpg(config).toOption
    opt.map(cpg =>
      AssignmentRefactorLayer.run(cpg)
      X2Cpg.applyDefaultOverlays(cpg)
      NormalizeCpgLayer.run(cpg)
      postProcessingPasses(cpg).foreach(_.createAndApply())
      cpg
    )
  }

  private def postProcessingPasses(
    cpg: Cpg,
    typeRecoveryConfig: XTypeRecoveryConfig = XTypeRecoveryConfig(iterations = 3),
    setKnownTypesConfig: XTypeStubsParserConfig = XTypeStubsParserConfig()
  ): List[CpgPassBase] = {
    // remove ComposerAutoloadPass. see https://github.com/joernio/joern/issues/4918
    List(new PhpTypeStubsParserPass(cpg, setKnownTypesConfig))
      ++ new PhpTypeRecoveryPassGenerator(cpg, typeRecoveryConfig).generate() :+ PhpTypeHintCallLinker(cpg)
  }
}

object PhpCpgGenerator {
  private lazy val parserBin = FileSys.copyResource("bin/php-parser.phar").toString
  private lazy val phpParser: PhpParser = {
    val config = Php2CpgConfig(phpParserBin = Some(parserBin))
    PhpParser.getParser(config).get
  }

  /** Expand the `--exclude-dirs` values into absolute directory paths.
    *
    * A value that contains a path separator is resolved relative to `root` (the previous behaviour). A bare directory
    * name such as `vendor` is matched against the name of every directory below `root`, so nested vendor directories
    * like `tools/syndication/vendor` are excluded as well.
    */
  private def expandExcludedDirs(root: Path, dirs: Seq[String]): Seq[String] = {
    dirs.flatMap { dir =>
      val hasSeparator = dir.contains('/') || dir.contains('\\')
      if (hasSeparator) Seq(root.resolve(dir).toAbsolutePath.toString)
      else {
        val matched = PhpCpgGenerator.collectDirectoriesNamed(root, dir)
        if (matched.isEmpty) Seq(root.resolve(dir).toAbsolutePath.toString) else matched
      }
    }
  }

  private def collectDirectoriesNamed(root: Path, name: String): Seq[String] = {
    if (!Files.isDirectory(root)) Seq.empty
    else {
      val result = scala.collection.mutable.ArrayBuffer.empty[String]
      val stream = Files.walk(root)
      try {
        stream
          .filter(path => Files.isDirectory(path) && path.getFileName.toString == name)
          .forEach(path => result += path.toAbsolutePath.toString)
      } finally stream.close()
      result.toSeq
    }
  }

  def runDataFlowLayer(cpg: Cpg): Unit = {
    // override default semantics of OssDataFlow
    implicit val semantics: Semantics = SemanticsGenerator.genericSemantic(Languages.PHP)
    val context                       = new LayerCreatorContext(cpg)
    val options                       = new OssDataFlowOptions(20000)
    val layer                         = new OssDataFlow(options)
    layer.run(context)
  }

  def runEnhanceLayer(cpg: Cpg, iterations: Option[Int] = Some(1))(implicit ctx: Api): Unit = {
    IterativeDynamicCallLayer.run(cpg, ctx.vsa, enhanced = true, fixJoernCallGraph = false, iterations = iterations)
    GlobalVariableFlowLayer.run(cpg, ctx.globalDefUse())
  }
}
