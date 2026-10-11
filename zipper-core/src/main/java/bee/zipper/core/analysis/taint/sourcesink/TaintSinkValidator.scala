package bee.zipper.core.analysis.taint.sourcesink

import bee.zipper.api.solver.sym.term.{BoolLiteral, StringLiteral}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.semantic.SemanticsGenerator
import bee.zipper.core.vuln.VulnKind
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages}
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

object TaintSinkValidator {
  def create(cpg: Cpg, vsa: ValueSetResult): TaintSinkValidator = {
    val language = cpg.metaData.language.head
    language match {
      case Languages.PHP       => new PHPTaintSinkValidator(cpg, vsa)
      case Languages.PYTHONSRC => new PythonTaintSinkValidator(cpg, vsa)
      case _ => throw new IllegalArgumentException(s"unsupported language: ${cpg.metaData.language.head}")
    }
  }
}

/** Checks if a given taint sink leads to a vulnerability by validating it against specific vulnerability kinds (e.g.,
  * XSS, Code Injection)
  */
trait TaintSinkValidator {
  def validate(sink: TaintSink, kind: String): Boolean
}

class PythonTaintSinkValidator(cpg: Cpg, vsa: ValueSetResult) extends TaintSinkValidator {
  def validate(sink: TaintSink, kind: String): Boolean = true
}

class PHPTaintSinkValidator(cpg: Cpg, vsa: ValueSetResult) extends TaintSinkValidator {

  /** validates a given sink against a specified vulnerability kind
    */
  def validate(sink: TaintSink, kind: String): Boolean = {
    sink match {
      case CallArgumentSink(call, _) =>
        kind match {
          case VulnKind.Xss           => validateXSS(call)
          case VulnKind.CodeInjection => validateCodeInjection(call)
          case _                      => true
        }
      case _ => true
    }
  }

  private implicit val context: EngineContext = {
    // The original approach with taintSemantic was problematic.
    // Placing fopen on the sink list prevented the proper tracking of its data flow.
    val semantic = SemanticsGenerator.genericSemantic(Languages.PHP)
    semantic.initialize(cpg)
    EngineContext(semantic)
  }

  private def validateXSS(call: Call): Boolean = {
    call.name match {
      case "print_r" =>
        // when `return` parameter is set to true, print_r() will return the information rather than print it
        call.argumentOption(2) match {
          case Some(arg2) =>
            vsa.ptsOf(call, arg2).exists {
              case BoolLiteral(false) => true
              case _                  => false
            }
          case None => true
        }
      case _ => true
    }
  }

  private val fopenCallsites = cpg.call("fopen").toList
  private def validateCodeInjection(call: Call): Boolean = {
    call.name match {
      case "fputs" =>
        // step1. find reachable `fopen` callsites
        val handlers = call.argumentOption(1).toList
        val reachableFopens =
          handlers
            .reachableByFlows(fopenCallsites)
            .flatMap(_.elements.headOption.collect { case c: Call => c })
            .distinct
        // step2. evaluate the file name arguments for the `fopen` calls
        val fileNames =
          reachableFopens
            .flatMap(_.argumentOption(1))
            .flatMap(arg => vsa.ptsOf(arg, arg, partialEval = true))
            .collect { case StringLiteral(s) => s }
        // step3: check if any file name ends with `.php` (indicating a possible injection)
        fileNames.exists(_.endsWith(".php"))
      case "file_put_contents" =>
        val fileNames =
          call
            .argumentOption(1)
            .toList
            .flatMap(arg => vsa.ptsOf(arg, arg, partialEval = true))
            .collect { case StringLiteral(s) => s }
        fileNames.exists(_.endsWith(".php"))
      case _ => true
    }
  }
}
