package bee.zipper.core.cpgcreation

import io.shiftleft.codepropertygraph.cpgloading.CpgLoader
import io.shiftleft.codepropertygraph.generated.Cpg

trait CpgGenerator {
  def input: String

  def output: Option[String]

  def mkCpg: Option[Cpg]
}

object CpgGenerator {
  def loadCpg(filename: String): Option[Cpg] = {
    try {
      Some(CpgLoader.load(filename))
    } catch {
      case _: Exception => None
    }
  }
}
