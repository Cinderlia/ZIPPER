package bee.zipper.core.analysis.taint.sourcesink

import bee.zipper.core.analysis.graph.vfg.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.core.vuln.{SanitizerManager, SourceSinkSpecManager}
import bee.zipper.util.AnyExtension.*
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages, Operators}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.MemberAccess

import scala.collection.mutable
import scala.util.control.Breaks.*

object TaintSourceSearcher {
  def create(
    cpg: Cpg,
    vfg: Vfg,
    enableWrapperFinder: Boolean = false,
    enableIndirectSuperGlobalFetching: Boolean = true
  ): TaintSourceSearcher = {
    val language = cpg.metaData.language.head
    language match {
      case Languages.PHP => PHPTaintSourceSearcher(cpg, vfg, enableWrapperFinder, enableIndirectSuperGlobalFetching)
      case Languages.PYTHONSRC => PythonTaintSourceSearcher(cpg, vfg)
      case _                   => throw new IllegalArgumentException(s"unsupported language: $language")
    }
  }
}

trait TaintSourceSearcher {

  /** Searches for all taint sinks and their wrappers in the CPG.
    */
  def search(): (List[CfgNode], List[Method])
}

class PythonTaintSourceSearcher(cpg: Cpg, vfg: Vfg) extends TaintSourceSearcher {
  override def search(): (List[CfgNode], List[Method]) = {
    val sources: List[CfgNode] = MethodCallSearcher.search()
    (sources, List.empty)
  }

  private object MethodCallSearcher {
    def search(): List[Call] = {
      val specs = SourceSinkSpecManager
        .getSource(Languages.PYTHONSRC)
        .methods

      val calls = cpg.call.filter(_.receiver.nonEmpty).toList
      calls.filter(call =>
        specs.exists(spec =>
          spec.methodName == call.name && (
            spec.receiverName match
              case Some(expectedReceiver) => isMatchedReceiver(call, expectedReceiver)
              case None                   => true
          )
        )
      )
    }

    private def isMatchedReceiver(call: Call, pattern: String): Boolean = {
      // pysrc2cpg will convert method call with complex receiver to block.
      // for example `flask.request.args.get("param")` will be converted to:
      //   tmp0 = flask.request.args
      //   tmp0.get("param")
      //
      // Note that the representation of the receiver is different from php2cpg
      // x.get() =>
      //    receiver = [operator.fieldAccess(x, get)]
      //    name = "get"
      //    args = []
      val receiver = call.receiver.head.code.split('.').head
      if (receiver.startsWith("tmp")) {
        call
          .getClosest[Block]
          .ast
          .assignment
          .exists(x => x.target.exists(_.code == receiver) && x.source.exists(_.code.matches(pattern)))
      } else
        receiver.matches(pattern)
    }
  }
}

class PHPTaintSourceSearcher(
  cpg: Cpg,
  vfg: Vfg,
  enableWrapperFinder: Boolean = false,
  enableIndirectSuperGlobalFetching: Boolean = true
) extends TaintSourceSearcher {
  private val language                    = cpg.metaData.language.head
  private val typeSanitizedRequestNames   = identifyTypeSanitizedRequestNames()
  private val directSuperGlobalFetching   = locateDirectSuperGlobalFetching()
  private val indirectSuperGlobalFetching = locateIndirectSuperGlobalFetching(maxDepth = 5)
  private val functionCalls               = locateFunctionCalls()
  private val methodCalls                 = locateMethodCalls()

  override def search(): (List[CfgNode], List[Method]) = identifySourcesAndWrappers()

  private def identifySourcesAndWrappers(): (List[CfgNode], List[Method]) = {
    def isLiteralFetching(call: Call): Boolean = {
      call.argumentOption(2) match {
        case Some(lit: Literal) if lit.isStr => true
        case _                               => false
      }
    }

    val discoveredSources = mutable.Set.empty[CfgNode]
    val detectedWrappers  = mutable.Set.empty[Method]

    val superGlobalFetching =
      if (enableIndirectSuperGlobalFetching)
        directSuperGlobalFetching ++ indirectSuperGlobalFetching
      else
        directSuperGlobalFetching
    val (literalFetching, nonLiteralFetching) = superGlobalFetching.partition(isLiteralFetching)

    discoveredSources ++= literalFetching
    discoveredSources ++= functionCalls
    discoveredSources ++= methodCalls
    if (!enableWrapperFinder) {
      discoveredSources ++= nonLiteralFetching
    } else {
      val finder = new PHPTaintSourceWrapperFinder(vfg, language)
      nonLiteralFetching.foreach(source =>
        val worklist = mutable.Queue.empty[(CfgNode, Boolean)]
        val visited  = mutable.Set.empty[CfgNode]
        worklist += ((source, false))
        while (worklist.nonEmpty) {
          val (node, retry) = worklist.dequeue()
          if (!visited.contains(node)) {
            visited.add(node)
            val finding = finder.isInWrapper(node)
            import finding.*
            if (inWrapper) {
              if (!isSanitized) {
                callsites.foreach(c => worklist += ((c, true)))
              }
            } else {
              discoveredSources += node
              if (retry) {
                detectedWrappers ++= node.as[Call].callee(NoResolve)
              }
            }
          }
        }
      )
    }
    (discoveredSources.toList, detectedWrappers.toList)
  }

  private def locateDirectSuperGlobalFetching(): List[Call] = {
    val indexAccesses = cpg.call(Operators.indexAccess).toList
    val rawSources = SourceSinkSpecManager
      .getSource(language)
      .globals
      .flatMap(globVar =>
        val name  = globVar.name
        val calls = indexAccesses.where(_.argument(1).code(s".*$name"))
        filterAllowedKey(globVar.allowKeys, calls)
      )
    filterSanitizedSources(rawSources)
  }

  private def locateIndirectSuperGlobalFetching(maxDepth: Int): List[Call] = {
    def traverseDataFlow(node: CfgNode): List[Call] = {
      def isTargetNode(prev: CfgNode, curr: CfgNode): Boolean = {
        curr match {
          // prev is used by an indexAccess operator, such as `$data = $_GET; $data["x"]`
          case call: Call if call.name == Operators.indexAccess && call.argument.size >= 2 =>
            val baseCode = call.argument(1).code
            val index    = call.argument(2)
            !baseCode.contains("tmp") // joern tmp variable
            && baseCode == prev.code
            && index.is[Literal]
            && index.as[Literal].isStr
          case _ => false
        }
      }

      def isValidNode(prev: CfgNode, curr: CfgNode): Boolean = {
        def isContainerOf(container: Call, element: CfgNode): Boolean = {
          MemberAccess.isGenericMemberAccessName(container.name)
          && container.argument(1).code == element.code
        }

        curr match {
          // foo($_GET)
          case parameter: MethodParameterIn => true
          case identifier: Identifier =>
            prev match {
              // `$SESSION['x']` is the container of `$SESSION`
              case call: Call if isContainerOf(call, identifier) => false
              case _                                             => true
            }
          case call: Call if !isContainerOf(call, prev) => true
          case _                                        => false
        }
      }

      val detectedSources = mutable.ListBuffer.empty[CfgNode]
      val worklist        = mutable.Queue.empty[(CfgNode, Int)]
      val visited         = mutable.Set.empty[CfgNode]
      worklist += ((node, 0))
      while (worklist.nonEmpty) {
        val (curr, depth) = worklist.dequeue()
        if (!visited.contains(curr)) {
          visited.add(curr)
          if (depth < maxDepth) {
            vfg
              .getOutEdgesOf(curr)
              .foreach(edge =>
                val to = edge.to
                if (isTargetNode(curr, to)) {
                  detectedSources += to
                } else if (isValidNode(curr, to)) {
                  val nextDepth = edge match {
                    case _: SimpleVfgCallEdge => depth + 1
                    case _: SimpleVfgRetEdge  => depth - 1
                    case _                    => depth
                  }
                  worklist += ((to, nextDepth))
                }
              )
          }
        }
      }
      detectedSources.collectAll[Call].toList.distinct
    }

    val nameToAllowKeys = SourceSinkSpecManager
      .getSource(language)
      .globals
      .map(x => x.name -> x.allowKeys)
      .toMap

    val rawSources = nameToAllowKeys
      .flatMap((name, allowKeys) =>
        val sources = cpg.identifier(name).flatMap(traverseDataFlow)
        filterAllowedKey(allowKeys, sources)
      )
      .toList
    filterSanitizedSources(rawSources)
  }

  private def locateFunctionCalls(): List[Call] = {
    val allFunctionCalls = cpg.call.filter(_.receiver.isEmpty).toList
    SourceSinkSpecManager
      .getSource(language)
      .functions
      .flatMap(allFunctionCalls.name(_))
  }

  private def locateMethodCalls(): List[Call] = {
    val allMethodCalls = cpg.call.filter(_.receiver.nonEmpty).toList
    val sources = SourceSinkSpecManager
      .getSource(language)
      .methods
    allMethodCalls.filter(call =>
      sources.exists(source =>
        source.methodName == call.name && (
          (source.receiverName match {
            case Some(expectedReceiver) =>
              call.receiver.exists(_.code == expectedReceiver)
            case None => false
          }) || (source.typeName match {
            case Some(expectedTypeName) =>
              isMatchedTypeName(call, expectedTypeName)
            case None => false
          }) || (source.receiverName.isEmpty && source.typeName.isEmpty)
        )
      )
    )
  }

  /** Check if the call matches the expected type name by examining callee methods
    */
  private def isMatchedTypeName(call: Call, expectedTypeName: String): Boolean = {
    call.callee(NoResolve).exists(_.astParentFullName == expectedTypeName)
  }

  private def filterAllowedKey(allowKeys: Option[List[String]], calls: Iterator[Call]): Iterator[Call] = {
    def isAllowedKey(allowKeys: List[String], call: Call): Boolean = {
      call.argumentOption(2) match {
        case Some(lit: Literal) if lit.isStr => allowKeys.contains(lit.getString)
        case _                               => true
      }
    }

    allowKeys match {
      case Some(allowKeys) => calls.filter(isAllowedKey(allowKeys, _))
      case None            => calls
    }
  }

  private def filterSanitizedSources(rawSources: List[Call]): List[Call] = {
    def isSanitizedSource(call: Call): Boolean = {
      call.name match {
        case Operators.indexAccess =>
          call.argumentOption(2) match {
            case Some(literal: Literal) if literal.isStr =>
              typeSanitizedRequestNames.contains(literal.getString)
            case _ => false
          }
        case _ => false
      }
    }
    rawSources.filterNot(isSanitizedSource)
  }

  private def identifyTypeSanitizedRequestNames(): Set[String] = {
    val castBasedSanitization = cpg
      .call(Operators.cast)
      .filter(c => c.argumentOption(1).isDefined && c.argumentOption(2).isDefined)
      .filter(c => c.inAssignment.nonEmpty && !c.argumentOption(1).exists(_.code.contains("string")))
      .flatMap(_.argumentOption(2))
      .collect { case c: Call if c.name == Operators.indexAccess => c }
      .flatMap(_.argumentOption(2))
      .collect { case lit: Literal if lit.typeFullName == "string" => lit.getString }
      .toSet
    castBasedSanitization
  }
}

class PHPTaintSourceWrapperFinder(vfg: Vfg, language: String) {
  val wrapperMethods = mutable.Set.empty[Method]

  /** @param inWrapper
    *   whether source is in a wrapper function
    * @param isSanitized
    *   whether source is sanitized in wrapper
    * @param callsites
    *   the callsites of wrapper function
    */
  case class Result(inWrapper: Boolean, isSanitized: Boolean, callsites: Set[Call])

  private val sanitizers: Set[String] = {
    val x = SanitizerManager.getSanitizer(language).genericSanitizer.toSet
    val y: Set[String] = SanitizerManager
      .getSanitizer(language)
      .vulnSanitizer
      .values
      .flatMap(_.functions.map(_.name))
      .toSet
    x ++ y
  }

  private val blacklist = Set(PhpOperators.concatOp)

  /** find the wrapper function of `source`
    *
    * @return
    *   true and callsites of wrapper function if `source` is in it.
    */
  def isInWrapper(source: CfgNode): Result = {
    val container = source.method
    if (wrapperMethods.contains(container)) {
      val callsites = NoResolve.getMethodCallsites(container).collectAll[Call].toSet
      return Result(true, false, callsites)
    }

    val detectedCallsites = mutable.ListBuffer.empty[Call]
    val worklist          = mutable.Queue.empty[CfgNode]
    val visited           = mutable.Set.empty[CfgNode]
    var isWithinWrapper   = false
    var isSanitized       = false
    worklist += source
    breakable {
      while (worklist.nonEmpty) {
        val node = worklist.dequeue()
        if (!visited.contains(node)) {
          visited.add(node)
          vfg.getOutEdgesOf(node).foreach { edge =>
            edge match {
              case edge: SimpleVfgCallEdge =>
                // over-approximation
                worklist += edge.callsite
              case edge: SimpleVfgRetEdge =>
                isWithinWrapper = true
                detectedCallsites += edge.to.as[Call]
              case edge @ _ =>
                val to = edge.to
                worklist += to
            }
            isSanitized |= isEdgeSanitized(edge)
          }
        }
      }
    }
    val callsites = detectedCallsites.toSet
    Result(isWithinWrapper && matchesWrapperFeatures(callsites), isSanitized, callsites)
  }

  private def isEdgeSanitized(edge: VfgEdge): Boolean = {
    edge match {
      case e: SimpleVfgCallEdge => sanitizers.contains(e.callsite.name)
      case e: SimpleVfgRetEdge  => false
      case e @ _ =>
        e.to match {
          case call: Call => sanitizers.contains(call.name) || blacklist.contains(call.name)
          case _          => false
        }
    }
  }

  private def matchesWrapperFeatures(callsites: Set[Call]): Boolean = {
    def hasLiteralArgument(call: Call): Boolean = {
      call.argument.size <= 3 && call.argument.exists {
        case lit: Literal => lit.isStr
        case _            => false
      }
    }

    callsites.exists(hasLiteralArgument)
  }
}
