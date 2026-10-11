package bee.zipper.core.vuln

import bee.zipper.util.sys.FileSys
import io.circe.*
import io.circe.generic.auto.*
import io.circe.syntax.*

import java.nio.file.Files

case class GlobalVarSourceSpec(name: String, allowKeys: Option[List[String]] = None)

case class MethodCallSourceSpec(typeName: Option[String], receiverName: Option[String], methodName: String)

case class LanguageSourceSpec(
  globals: List[GlobalVarSourceSpec] = Nil,
  functions: List[String] = Nil,
  methods: List[MethodCallSourceSpec] = Nil
)

type TaintSourceSpec = Map[String, LanguageSourceSpec] // language -> language source

object TaintSourceSpec {
  def fromJson(json: String): Option[TaintSourceSpec] = {
    parser.decode[TaintSourceSpec](json).toOption
  }

  def toJson(sourceSpec: TaintSourceSpec): String = {
    sourceSpec.asJson.noSpaces
  }

  def merge(specs: List[TaintSourceSpec]): TaintSourceSpec = {
    specs
      .flatMap(_.toList)
      .groupBy(_._1)
      .view
      .mapValues { grouped =>
        val sources = grouped.map(_._2)
        LanguageSourceSpec(sources.flatMap(_.globals), sources.flatMap(_.functions), sources.flatMap(_.methods))
      }
      .toMap
  }
}

case class MethodCallSinkSpec(
  typeName: Option[String],
  receiverName: Option[String],
  methodName: String,
  args: Option[Seq[Int]] = None
)

/** @param name
  *   name of the function
  * @param args
  *   affected arguments. None indicates all arguments will be traced
  */
case class FunCallSinkSpec(name: String, args: Option[Seq[Int]] = None)

case class VulnerabilitySinkSpec(functions: List[FunCallSinkSpec] = Nil, methods: List[MethodCallSinkSpec] = Nil)

type LanguageSinkSpec = Map[String, VulnerabilitySinkSpec] // vulnerability kind -> vulnerability sink

type TaintSinkSpec = Map[String, LanguageSinkSpec] // language -> language sink

object TaintSinkSpec {
  def fromJson(json: String): Option[TaintSinkSpec] = {
    parser.decode[TaintSinkSpec](json).toOption
  }

  def toJson(sinkSpec: TaintSinkSpec): String = {
    sinkSpec.asJson.noSpaces
  }

  def merge(specs: List[TaintSinkSpec]): TaintSinkSpec = {
    specs
      .flatMap(_.toList) // convert into a flat list of (language, LanguageSink) pairs
      .groupBy(_._1)     // Group by language
      .view
      .mapValues { groupedLangSink =>
        groupedLangSink
          .map(_._2)        // extract all LanguageSink values for the same language
          .flatMap(_.toSeq) // convert each LanguageSink into a list of (vulnerability, VulnerabilitySink) pairs
          .groupBy(_._1)    // group by vulnerability kind
          .view
          .mapValues { groupedVulnSink =>
            val sinks = groupedVulnSink.map(_._2)
            VulnerabilitySinkSpec(
              functions = sinks.flatMap(_.functions).distinct,
              methods = sinks.flatMap(_.methods).distinct
            )
          }
          .toMap
      }
      .toMap
  }
}

object SourceSinkSpecManager {
  private var sources: TaintSourceSpec             = Map.empty
  private var sinks: TaintSinkSpec                 = Map.empty
  private var activeVulnKinds: Option[Set[String]] = None

  loadDefaultConfig()

  def loadSources(configs: List[String]): Unit = {
    val specs: List[TaintSourceSpec] = configs.map { content =>
      TaintSourceSpec
        .fromJson(content)
        .getOrElse(throw new RuntimeException(s"failed to parse source config"))
    }
    sources = TaintSourceSpec.merge(specs)
  }

  def loadSinks(configs: List[String]): Unit = {
    val specs: List[TaintSinkSpec] = configs.map { content =>
      TaintSinkSpec.fromJson(content).getOrElse(throw new RuntimeException(s"failed to parse sink config"))
    }
    sinks = TaintSinkSpec.merge(specs)
  }

  def loadDefaultConfig(): Unit = {
    val languageDirs = List("php", "pysrc", "jssrc")

    val sourceConfigs = languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/source/$lang")
        .map(path => Files.readString(path))
    }
    loadSources(sourceConfigs)

    val sinkConfigs = languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/sink/$lang")
        .map(path => Files.readString(path))
    }
    loadSinks(sinkConfigs)
  }

  /** Set active vulnerability kinds to filter sinks when retrieving them. If the set is empty, no filtering will be
    * applied (i.e., all kinds enabled).
    */
  def setActiveVulnKinds(kinds: Set[String]): Unit = {
    activeVulnKinds = if (kinds.nonEmpty) Some(kinds) else None
  }

  /** Clear the active vulnerability kind filter. */
  def clearActiveVulnKinds(): Unit = {
    activeVulnKinds = None
  }

  /** Load custom source configurations from file paths
    */
  def loadCustomSourceConfigs(filePaths: List[String]): Unit = {
    val configs = filePaths.map { path =>
      try {
        Files.readString(java.nio.file.Paths.get(path))
      } catch {
        case e: Exception =>
          throw new RuntimeException(s"Failed to read source config file: $path", e)
      }
    }
    loadSources(configs)
  }

  /** Load custom sink configurations from file paths
    */
  def loadCustomSinkConfigs(filePaths: List[String]): Unit = {
    val configs = filePaths.map { path =>
      try {
        Files.readString(java.nio.file.Paths.get(path))
      } catch {
        case e: Exception =>
          throw new RuntimeException(s"Failed to read sink config file: $path", e)
      }
    }
    loadSinks(configs)
  }

  /** Get default source configurations
    */
  private def getDefaultSourceConfigs(): List[String] = {
    val languageDirs = List("php", "pysrc", "jssrc")
    languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/source/$lang")
        .map(path => Files.readString(path))
    }
  }

  /** Get default sink configurations
    */
  private def getDefaultSinkConfigs(): List[String] = {
    val languageDirs = List("php", "pysrc", "jssrc")
    languageDirs.flatMap { lang =>
      FileSys
        .listResourceDir(s"taint/sink/$lang")
        .map(path => Files.readString(path))
    }
  }

  def getSource(language: String): LanguageSourceSpec = {
    sources.getOrElse(language, throw new RuntimeException(s"no source config for language $language"))
  }

  def getSink(language: String): LanguageSinkSpec = {
    val all = sinks.getOrElse(language, throw new RuntimeException(s"no sink config for language $language"))
    activeVulnKinds match {
      case Some(enabled) => all.filter { case (kind, _) => enabled.contains(kind) }
      case None          => all
    }
  }

  def allSources: TaintSourceSpec = sources

  def allSinks: TaintSinkSpec = sinks
}
