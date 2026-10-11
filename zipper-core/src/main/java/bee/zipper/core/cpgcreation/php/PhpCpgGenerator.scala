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

import java.nio.file.Paths

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
      val root  = Paths.get(input)
      val absOf = (p: String) => root.resolve(p).toAbsolutePath.toString
      excludeDirs.map(absOf) ++ excludeFiles.map(absOf)
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
