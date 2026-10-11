package bee.zipper.core.cpgcreation.pysrc

import bee.zipper.core.cpgcreation.CpgGenerator
import io.joern.pysrc2cpg.{Py2CpgOnFileSystem, Py2CpgOnFileSystemConfig}
import io.shiftleft.codepropertygraph.generated.Cpg

import java.nio.file.Paths

class PythonCpgGenerator(
  val input: String,
  val output: Option[String] = None,
  excludeDirs: Seq[String] = Seq.empty,
  excludeFiles: Seq[String] = Seq.empty
) extends CpgGenerator {
  override def mkCpg: Option[Cpg] = {
    val config = Py2CpgOnFileSystemConfig()
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
    val py2Cpg = new Py2CpgOnFileSystem()
    py2Cpg.createCpgWithOverlays(config).toOption
  }
}
