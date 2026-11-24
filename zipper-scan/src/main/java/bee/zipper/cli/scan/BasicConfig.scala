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
    description = Array("Exclude directories (comma-separated; a bare name excludes matching directories at any depth)")
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
  @CommandLine.Option(
    names = Array("--scan-scenarios"),
    split = ",",
    description = Array(
      "Scan scenarios: once-xss,once-sql,second-xss,second-sql,second-injection (comma-separated; default: all when enabled)"
    )
  )
  var scanScenarios: List[String] = null

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
    names = Array("--enable-twig-sinks"),
    description = Array("Model Twig template output (|raw) as an XSS sink (experimental)")
  )
  var enableTwigSinks: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-callback-flow"),
    description = Array("Resolve PHP callbacks passed to preg_replace_callback, array_map and friends")
  )
  var enableCallbackFlow: Boolean = true

  @CommandLine.Option(
    names = Array("--enable-extract-flow"),
    description = Array("Bridge `extract()` of a database row array with the variables it defines (experimental)")
  )
  var enableExtractFlow: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-output-buffer"),
    description = Array(
      "Connect output printed inside an ob_start/ob_get_clean window with the captured value (experimental)"
    )
  )
  var enableOutputBuffer: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-field-summary"),
    arity = "0..1",
    fallbackValue = "class",
    description = Array(
      "Bridge object field reads and writes across methods: `class` (same class only) " +
        "or `class+global` (also include-scope files that read $this-> fields)"
    )
  )
  var fieldSummary: String = ""

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
    names = Array("--enable-reachability-report"),
    paramLabel = "<path|debug>",
    description =
      Array("Generate reachability JSON reports; filtering remains controlled by --enable-reachability-analysis"),
    arity = "1"
  )
  var enableReachabilityReport: String = ""

  @CommandLine.Option(
    names = Array("--enable-ControlStructure"),
    description = Array("Add relevant control structures to taint paths")
  )
  var enableControlStructure: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-Implicit-taint"),
    description = Array(
      "Add implicit taint to taint paths, i.e. flags assigned under a tainted guard; requires --enable-ControlStructure"
    )
  )
  var enableImplicitTaint: Boolean = false

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
    names = Array("--narrow-unresolved-calls"),
    description = Array("Do not expand external/stub callees; their flows come from argument-to-result edges")
  )
  var enableNarrowUnresolvedCalls: Boolean = false

  @CommandLine.Option(
    names = Array("--enable-shared-result-table"),
    description = Array("Reuse dataflow engine results across probe searches (same sources and semantics)")
  )
  var enableSharedResultTable: Boolean = false

  @CommandLine.Option(
    names = Array("--symbolic-print-depth"),
    description = Array("Maximum depth when rendering symbolic values (default: 8; guards against cyclic structures)")
  )
  var symbolicPrintDepth: Int = 8

  @CommandLine.Option(
    names = Array("--custom-navi"),
    description = Array("Custom navigation chain configuration file path (JSON)")
  )
  var customNaviConfig: String = ""

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

  // Resolve `$x = $services->get(Foo::class)` style service locators so that `$x->m()` links to `Foo::m`
  @CommandLine.Option(
    names = Array("--enable-service-locator-type"),
    description = Array(
      "Infer the type of service-locator results ($this->getService(Foo::class), $services->get(Foo::class)) " +
        "and link method calls on them to the service class"
    )
  )
  var enableServiceLocatorType: Boolean = false

  // Model `include`/`require` as a shared variable scope: free variables of the included file become parameters of
  // its `<global>` method and are passed from the include call site
  @CommandLine.Option(
    names = Array("--enable-include-scope"),
    description = Array(
      "Treat include/require as a shared variable scope: variables defined in the including file flow into the " +
        "included file and across nested inclusions"
    )
  )
  var enableIncludeScope: Boolean = false
}
