package bee.zipper.cli.scan

import io.shiftleft.codepropertygraph.generated.Languages
import picocli.CommandLine
import picocli.CommandLine.{ArgGroup, Mixin, Option, Parameters}

import scala.compiletime.uninitialized
import java.util.{List, ArrayList}

// basic configuration for ZIPPER

class BasicConfig {
  @CommandLine.Option(names = Array("--output-dir"), description = Array("Output directory (default: ./output/)"))
  var outputDir: String = "./output/"

  // CPG output path (only applies when generating new CPG)
  @CommandLine.Option(
    names = Array("--cpg-out"),
    description = Array(
      "Path to store generated CPG file (.bin). If omitted, defaults to <output-dir>/cpg.bin. Only applies when using --src"
    )
  )
  var cpgLocation: String = ""

  @Mixin
  var projectConfig: ProjectConfig = new ProjectConfig

  @Mixin
  var engineConfig: EngineConfig = new EngineConfig
}

class ProjectConfig {
  @CommandLine.Option(
    names = Array("--language"),
    description = Array("Target language (supported: ${COMPLETION-CANDIDATES})"),
    completionCandidates = classOf[SupportedLanguages.AllCandidates]
  )
  var language: String = Languages.PHP

  @CommandLine.Option(
    names = Array("--exclude-dirs"),
    split = ",",
    description = Array("Exclude directories (comma-separated)")
  )
  var excludeDirs: List[String] = new ArrayList[String]()

  @CommandLine.Option(
    names = Array("--exclude-files"),
    split = ",",
    description = Array("Exclude files (comma-separated)")
  )
  var excludeFiles: List[String] = new ArrayList[String]()

  @CommandLine.Option(
    names = Array("--load-cpg"),
    paramLabel = "<cpg-location>",
    description = Array("Use an existing CPG file instead of generating")
  )
  var cpg: String = uninitialized

  @Parameters(paramLabel = "<project>", description = Array("Project path (must exist)"))
  var path: String = ""

  def isLoadingCpgMode: Boolean = cpg != null && cpg.nonEmpty
}

class EngineConfig {
  // value inference
  @CommandLine.Option(
    names = Array("--disable-enhanced-vsa"),
    negatable = true,
    description = Array("Enable enhanced value set analysis")
  )
  var enhancedValueSetAnalysis: Boolean = true

  // dynamic call resolution
  @CommandLine.Option(
    names = Array("--enable-tchecker-dynamic-call"),
    description = Array("Enable TChecker-style dynamic call resolution")
  )
  var enableTCheckerDynamicCall: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-enhanced-dynamic-call"),
    description = Array("Enable enhanced dynamic call resolution")
  )
  var enableEnhancedDynamicCall: Boolean = false

  @CommandLine.Option(
    names = Array("--fix-joern-call-graph"),
    description = Array("Fix Joern call graph during dynamic call resolution")
  )
  var fixJoernCallGraph: Boolean = false

  @CommandLine.Option(
    names = Array("--iterations"),
    description = Array("Number of iterations for dynamic calls resolution (default: 1)")
  )
  var iterations: Integer = 1

  // taint analysis configuration
  @CommandLine.Option(
    names = Array("--enable-phpjoern-taint-analysis"),
    description = Array("Enable PHPJoern-style taint analysis")
  )
  var enablePHPJoernTaintAnalysis: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-global-data-dependency"),
    description = Array("Enable global data dependency analysis")
  )
  var enableGlobalDataDependency: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-object-data-dependency"),
    description = Array("Enable object data dependency analysis")
  )
  var enableObjectDataDependency: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-ondemand-alias-analysis"),
    description = Array("Enable on-demand alias analysis")
  )
  var enableOnDemandAliasAnalysis: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-deduplicate-flow"),
    description = Array("Enable deduplicate flow for taint analysis")
  )
  var enableDeduplicateFlow: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-reachability-analysis"),
    description = Array("Enable reachability analysis for taint analysis")
  )
  var enableReachabilityAnalysis: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-custom-sanitizer-recognizer"),
    description = Array("Enable custom sanitizer recognizer for recursive sanitizers")
  )
  var enableCustomSanitizer: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-sanitizer-keyword-match"),
    description = Array("Enable matching sanitizer keywords in code field of taint flow")
  )
  var enableSanitizerKeywordMatching: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-wordpress"),
    description = Array(
      "Enable WordPress hook and option resolution (add_filter/add_action, apply_filters/do_action, update_option/get_option)"
    )
  )
  var enableWordPress: Boolean = false

  // Custom configuration file paths for taint analysis
  @CommandLine.Option(
    names = Array("--custom-source"),
    split = ",",
    description = Array("Custom source configuration file paths (comma-separated)")
  )
  var customSourceConfigs: List[String] = new ArrayList[String]()

  @CommandLine.Option(
    names = Array("--custom-sink"),
    split = ",",
    description = Array("Custom sink configuration file paths (comma-separated)")
  )
  var customSinkConfigs: List[String] = new ArrayList[String]()

  @CommandLine.Option(
    names = Array("--custom-sanitizer"),
    split = ",",
    description = Array("Custom sanitizer configuration file paths (comma-separated)")
  )
  var customSanitizerConfigs: List[String] = new ArrayList[String]()

  // Enable indirect super global fetching for taint analysis
  @CommandLine.Option(
    names = Array("--enable-indirect-superglobal-fetching"),
    description = Array(
      "Enable indirect super global fetching for taint source detection, which might lead to false positives"
    )
  )
  var enableIndirectSuperGlobalFetching: Boolean = true

  // Enable filtering by vulnerability kinds (e.g., Xss, SqlInjection). Comma-separated list.
  @CommandLine.Option(
    names = Array("--vulnkind"),
    split = ",",
    description = Array("Only enable specified vulnerability kinds (comma-separated), e.g., Xss,SqlInjection")
  )
  var enabledVulnKinds: List[String] = new ArrayList[String]()
}
