package bee.zipper.cli.scan

import io.shiftleft.codepropertygraph.generated.Languages

object SupportedLanguages {
  private val STATIC = Set(Languages.PHP)

  private val ALL = STATIC

  def validateAll(lang: String): Either[String, Unit] = {
    if (ALL.contains(lang)) Right(())
    else Left(s"unsupported language '$lang'")
  }

  def validateStatic(lang: String): Either[String, Unit] = {
    if (STATIC.contains(lang)) Right(())
    else Left(s"unsupported language '$lang'")
  }

  class AllCandidates extends java.util.ArrayList[String] {
    SupportedLanguages.ALL.foreach(add)
  }
}
