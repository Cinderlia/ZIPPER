package bee.zipper.core.vuln

import bee.zipper.util.sys.FileSys

import java.nio.file.Files

object SanitizerManager {
  private var sanitizers: SanitizerSpec            = Map.empty
  private var activeVulnKinds: Option[Set[String]] = None

  loadDefaultConfig()

  def loadSanitizers(configs: List[String]): Unit = {
    val specs: List[SanitizerSpec] = configs.map { content =>
      SanitizerSpec
        .fromJson(content)
        .getOrElse(throw new RuntimeException(s"failed to parse sanitizer config"))
    }
    sanitizers = SanitizerSpec.merge(specs)
  }

  /** Load default sanitizer configurations from predefined directories */
  def loadDefaultConfig(): Unit = {
    val languageDirs = List("php", "pysrc", "jssrc")

    val sanitizerConfigs = languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/sanitizer/$lang")
        .map(path => Files.readString(path))
    }
    loadSanitizers(sanitizerConfigs)
  }

  /** Set active vulnerability kinds to filter vuln-specific sanitizers when retrieving them. */
  def setActiveVulnKinds(kinds: Set[String]): Unit = {
    activeVulnKinds = if (kinds.nonEmpty) Some(kinds) else None
  }

  /** Clear the active vulnerability kind filter. */
  def clearActiveVulnKinds(): Unit = {
    activeVulnKinds = None
  }

  /** Load custom sanitizer configurations from file paths
    */
  def loadCustomSanitizerConfigs(filePaths: List[String]): Unit = {
    val configs = filePaths.map { path =>
      try {
        Files.readString(java.nio.file.Paths.get(path))
      } catch {
        case e: Exception =>
          throw new RuntimeException(s"Failed to read sanitizer config file: $path", e)
      }
    }
    loadSanitizers(configs)
  }

  /** Get default sanitizer configurations
    */
  private def getDefaultSanitizerConfigs(): List[String] = {
    val languageDirs = List("php", "pysrc", "jssrc")
    languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/sanitizer/$lang")
        .map(path => Files.readString(path))
    }
  }

  def getSanitizer(language: String): LanguageSanitizers = {
    val all = sanitizers.getOrElse(language, throw new RuntimeException(s"no sanitizer config for language $language"))
    activeVulnKinds match {
      case Some(enabled) => all.copy(vulnSanitizer = all.vulnSanitizer.filter { case (k, _) => enabled.contains(k) })
      case None          => all
    }
  }

  def allSanitizers: SanitizerSpec = sanitizers
}
