package bee.zipper.core.analysis.taint

import bee.zipper.api.solver.sym.extend.SymbolicArray
import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.analysis.model.cs.PathCallGraph
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.vuln.{FunSanitizer, SanitizerManager, VulnKind}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*
import org.apache.commons.text.similarity.JaccardSimilarity

/** Filter taint paths based on feasibility and sanitization
  */
class PathFilter(
  cpg: Cpg,
  vsa: ValueSetResult,
  language: String,
  exploitMode: Boolean,
  enableCustomSanitizer: Boolean,
  enableKeywordMatching: Boolean
) {
  private val reachAnalysis = new ReachabilityAnalysis(vsa)

  private val typeSanitizerNames   = SanitizerManager.getSanitizer(language).typeSanitizer
  private val stringSanitizerNames = SanitizerManager.getSanitizer(language).genericSanitizer
  private val xssCustomSanitizerNames =
    if (!enableCustomSanitizer) Set.empty
    else {
      val recognizer = new XssCustomSanitizerRecognizer(cpg, language)
      recognizer.recognize().map(m => m.name).toSet
    }

  def isReachable(taintPath: TaintPath): Boolean = reachAnalysis.isReachable(taintPath.path)

  /** joern-dataflow engine can't filter all the paths contains sanitizers, so we need to filter them again.
    */
  def isValid(taintPath: TaintPath): Boolean = {
    // functions with optional allowed arg indexes (args=None means all args)
    val vulnSan = SanitizerManager
      .getSanitizer(language)
      .vulnSanitizer
      .getOrElse(taintPath.kind, bee.zipper.core.vuln.VulnSanitizer())
    val vulnSanFunSpecs: List[FunSanitizer] = vulnSan.functions
    val vulnSanFunNames: Set[String]        = vulnSanFunSpecs.map(_.name).toSet
    val vulnSanMethods                      = vulnSan.methods.toSet
    val vulnSanRegexes                      = vulnSan.regexes.toSet
    val matchingKeywords = {
      // Only use generic/string sanitizers for keyword matching to avoid bypassing args-aware logic
      val part1 = stringSanitizerNames.map(x => x + "(")
      val part2 = Set.empty[String]
      part1 ++ part2
    }

    // Search any argument of `call` that already appears earlier in the path before `call`
    def inferTaintedArgIndexFromPrefix(pathPrefix: List[CfgNode], call: Call): Option[Int] = {
      val args           = call.argument.l
      val receiverAsArg0 = call.receiver.headOption.exists(rcv => args.headOption.contains(rcv))
      val argStart       = if (receiverAsArg0) 1 else 0
      // prefer the argument that appears last in the prefix (closest to the call along the path)
      val candidates = args.zipWithIndex.collect {
        case (arg, idx) if idx >= argStart && pathPrefix.contains(arg) => (arg, idx)
      }
      if (candidates.nonEmpty) {
        val (_, bestArgIdx) = candidates.maxBy { case (arg, _) => pathPrefix.lastIndexOf(arg) }
        Some((bestArgIdx - argStart) + 1)
      } else None
    }

    def isMatchFunSanitizer(call: Call, taintedArgIndex: Option[Int]): Boolean = {
      // 1) Built-in configured function sanitizers with optional args
      val builtinHit = vulnSanFunSpecs.exists { fs =>
        if (fs.name != call.name) false
        else
          fs.args match {
            case None =>
              fs.excludeArgs match {
                case None          => true // pure wildcard
                case Some(exIdxes) => taintedArgIndex.exists(idx => !exIdxes.contains(idx))
              }
            case Some(indexes) =>
              // args has precedence; antiArgs ignored when args is defined
              taintedArgIndex.exists(indexes.contains)
          }
      }
      // 2) Custom recognized XSS sanitizers (no args awareness for now)
      val customXssHit = if (taintPath.kind == VulnKind.Xss) xssCustomSanitizerNames.contains(call.name) else false
      builtinHit || customXssHit
    }

    /** Check whether the given call matches any configured method sanitizers. A match happens when:
      *   1. The method name is identical, **and** 2. (receiverName is defined and equals the receiver code) **OR**
      *      (typeName is defined and matches the callee's parent full name) **OR** neither receiverName nor typeName is
      *      defined (wild-card).
      */
    def isMatchMethodSanitizer(call: Call, taintedArgIndex: Option[Int]): Boolean = {
      // Extract receiver code and static type name (if available)
      val receiverNameOpt: Option[String] = call.receiver.headOption.map(_.code)
      val typeNameOpt: Option[String]     = call.callee(NoResolve).headOption.map(_.astParentFullName)

      vulnSanMethods.exists { ms =>
        // Method name must match first
        if (ms.methodName != call.name) false
        else {
          val receiverMatches = ms.receiverName.exists(_ == receiverNameOpt.getOrElse(""))
          val typeMatches     = ms.typeName.exists(_ == typeNameOpt.getOrElse(""))
          // When both receiverName and typeName are absent we treat it as a wildcard match.
          val wildcard  = ms.receiverName.isEmpty && ms.typeName.isEmpty
          val baseMatch = receiverMatches || typeMatches || wildcard
          if (!baseMatch) false
          else {
            ms.args match {
              case Some(indexes) => taintedArgIndex.exists(indexes.contains)
              case None =>
                ms.excludeArgs match {
                  case None          => true
                  case Some(exIdxes) => taintedArgIndex.exists(idx => !exIdxes.contains(idx))
                }
            }
          }
        }
      }
    }

    /** The two matching methods above still result in false positives, so we additionally use the code field of the
      * call node to match sanitizer names.
      *
      * TODO: we need check above two matching functions carefully to remove this method
      */
    def isCodeMatchSanitizer(call: Call): Boolean = {
      if (!enableKeywordMatching) false
      else {
        val code = call.code
        matchingKeywords.exists(keyword => code.contains(keyword))
      }
    }

    /** This function checks for a known bug in EdgeValidator of joern-dataflow
      *
      * @return
      *   true if it passes the check
      */
    def verifyConditionalOperator(prev: CfgNode, node: CfgNode): Boolean = {
      // here is one bug due to EdgeValidator in joern-dataflow.
      //   function foo() {
      //     return $_GET["x"];
      //   }
      //   $output = foo() ? $y : $z; // taint is propagated by foo() that can't be handled by EdgeValidator
      //   echo $output;
      node match {
        case call: Call
            if call.name == Operators.conditional
              && call.argument.size == 3
              && call.argument.head == prev =>
          false
        case _ => true
      }
    }

    def isMatchSanitizerRegex(call: Call, threshold: Double = 0.95): Boolean = {
      // used to do VSA context-sensitively
      implicit val pathCallGraph: Option[PathCallGraph] = Some(PathCallGraph.fromValueFlow(taintPath, call))

      def isMatchSanitizer(patterns: Set[String]): Boolean = {
        vulnSanRegexes.exists(sanitizerRegex =>
          patterns.exists(pattern => similarity(sanitizerRegex, pattern) >= threshold)
        )
      }

      def handlePregReplaceFamily(call: Call): Boolean = {
        call.argumentOption(1) match {
          case Some(arg1) =>
            val patterns = vsa.ptsOf(call, arg1).flatMap {
              case StringLiteral(pattern) => Set(pattern)
              case array: SymbolicArray   => array.getConcrete.values.collect { case StringLiteral(pattern) => pattern }
              case _                      => Set.empty
            }
            isMatchSanitizer(patterns)
          case _ => false
        }
      }

      def handleStrtr(call: Call): Boolean = {
        val argumentSize = call.argument.size
        if (argumentSize == 2) {
          // strtr(string, array)
          val patterns = vsa
            .ptsOf(call, call.argument(2))
            .collect { case array: SymbolicArray => array.getConcrete.keySet }
            .flatten
          isMatchSanitizer(patterns)
        } else if (argumentSize == 3) {
          // strtr(string, from, to)
          val patterns = vsa.ptsOf(call, call.argument(2)).collect { case StringLiteral(pattern) => pattern }
          isMatchSanitizer(patterns)
        } else false
      }

      call.name match {
        case "preg_replace" | "preg_replace_callback" => handlePregReplaceFamily(call)
        case "strtr"                                  => handleStrtr(call)
        case _                                        => false
      }
    }

    def isValidNode(node: CfgNode): Boolean = {
      node match {
        case call: Call =>
          if (typeSanitizerNames.contains(call.name)) return false
          // If in exploit mode, we don't filter out paths containing sanitizers, since the goal is to attempt bypassing them
          if (exploitMode) return true
          val isSanitized =
            stringSanitizerNames.contains(call.name)
              || isMatchSanitizerRegex(call)
              || isCodeMatchSanitizer(call)
          !isSanitized
        case _ => true
      }
    }

    taintPath.path match {
      case path if path.size < 2 => true
      case path =>
        path.forall(isValidNode) &&
        path.sliding(2).forall {
          case Seq(prev, curr: Call) =>
            verifyConditionalOperator(prev, curr) && {
              if (exploitMode) true
              else {
                val prefix            = path.takeWhile(_ != curr)
                val taintedIdx        = inferTaintedArgIndexFromPrefix(prefix, curr)
                val isFunSanitized    = isMatchFunSanitizer(curr, taintedIdx)
                val isMethodSanitized = isMatchMethodSanitizer(curr, taintedIdx)
                !(isFunSanitized || isMethodSanitized)
              }
            }
          case Seq(prev, curr) => verifyConditionalOperator(prev, curr)
          case _               => false // sliding(2) always returns size-2 windows, so this is defensive
        }
    }
  }

  private val jaroWink = new JaccardSimilarity()

  private def similarity(s1: String, s2: String): Double = {
    jaroWink.apply(s1, s2)
  }
}
