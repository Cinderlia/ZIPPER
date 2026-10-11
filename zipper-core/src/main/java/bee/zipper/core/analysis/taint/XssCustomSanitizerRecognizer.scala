package bee.zipper.core.analysis.taint

import bee.zipper.core.semantic.SemanticsGenerator
import bee.zipper.core.vuln.{SanitizerManager, VulnKind}
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Method}
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory
import scala.util.matching.Regex

/** Recognizes custom sanitizers based on specific patterns (currently only support PHP and XSS vulnerability).
  */
class XssCustomSanitizerRecognizer(cpg: Cpg, language: String) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  def recognize(): List[Method] = {
    findRecursiveSanitizer()
  }

  private def findRecursiveSanitizer(): List[Method] = {
    // function form_prep($str = '', $field_name = '') {
    //   if (is_array($str)) {
    //     foreach ($str as $key => $val)
    //       $str[$key] = form_prep($val);
    //     return $str;
    //   }
    //   $str = htmlspecialchars($str);
    //   return $str;
    // }
    def isRecursiveSanitizer(method: Method, sanitizerSite: Call): Boolean = {
      logger.info(s"Check if function <${method.name}> is a recursive sanitizer")
      // step1. check if the method is a function (not a method of a class)
      val typeDecl = method.typeDecl
      if (typeDecl.nonEmpty && typeDecl.get.name != "<global>")
        return false
      // step2. check if the function has parameters and return value
      val parameters = method.parameter.toList
      val returns    = method.methodReturn.toReturn.toList
      if (parameters.isEmpty || returns.size < 2)
        return false
      // step3. check if the function has a call to itself
      val option = method.cfgNode.isCall.filter(_.receiver.isEmpty).find(c => c.name == method.name)
      if (option.isEmpty)
        return false
      val recursiveSite = option.get
      // step4. check if exits a data-flow from the parameter to the recursive call and return sites
      hasIntraDataFlow(parameters, recursiveSite.argument.toList)
      && hasIntraDataFlow(parameters, sanitizerSite.argument.toList)
      && hasIntraDataFlow(List(sanitizerSite), returns.argumentOut.toList)
    }

    val basicSanitizerSites = {
      val functionNames =
        SanitizerManager
          .getSanitizer(language)
          .vulnSanitizer
          .get(VulnKind.Xss)
          .map(_.functions.map(_.name))
          .getOrElse(Nil)
      if (functionNames.isEmpty) List.empty
      else {
        val regex = functionNames.map(Regex.quote).mkString("|")
        cpg.call(regex).toList
      }
    }
    basicSanitizerSites
      .map(site => site.method -> site)
      .distinctBy(_._1)
      .filter { case (method, site) => isRecursiveSanitizer(method, site) }
      .map(_._1)
      .distinct
  }

  private implicit val intraEngineContext: EngineContext =
    EngineContext(semantics = SemanticsGenerator.genericSemantic(language), config = EngineConfig(maxCallDepth = 0))

  private def hasIntraDataFlow(sources: List[CfgNode], sinks: List[CfgNode]): Boolean = {
    if (sinks.isEmpty || sources.isEmpty) return false
    sinks.reachableByFlows(sources).nonEmpty
  }
}
