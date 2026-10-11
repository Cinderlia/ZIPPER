package bee.zipper.core.cpgcreation.jssrc

import bee.zipper.core.cpgcreation.CpgGenerator
import bee.zipper.core.cpgcreation.jssrc.JavaScriptCpgGenerator.init
import bee.zipper.util.sys.FileSys
import io.joern.jssrc2cpg.{JsSrc2Cpg, Config as JavaScriptConfig}
import io.shiftleft.codepropertygraph.generated.Cpg

import java.nio.file.Paths

class JavaScriptCpgGenerator(
  val input: String,
  val output: Option[String] = None,
  excludeDirs: Seq[String] = Seq.empty,
  excludeFiles: Seq[String] = Seq.empty
) extends CpgGenerator {
  override def mkCpg: Option[Cpg] = {
    init()
    val config = JavaScriptConfig()
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
    val jsSrc2Cpg = new JsSrc2Cpg()
    jsSrc2Cpg.createCpgWithOverlays(config).toOption
  }
}

object JavaScriptCpgGenerator {
  private def init(): Unit = {
    // note that the path of astgen is hard-coded in jssrc2cpg
    FileSys.copyResource("bin/jssrc-astgen/astgen-linux", "bin/astgen/astgen-linux")
    FileSys.copyResource("bin/jssrc-astgen/astgen-win.exe", "bin/astgen/astgen-win.exe")
  }
}
