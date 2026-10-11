package bee.zipper.core.analysis.taint.sourcesink

import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.core.vuln.{FunCallSinkSpec, MethodCallSinkSpec, SourceSinkSpecManager}
import io.shiftleft.codepropertygraph.generated.nodes.{Block, Call}
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages}
import io.shiftleft.semanticcpg.language.*

object TaintSinkSearcher {

  /** Factory Method: Creates a language-specific taint sink searcher instance
    */
  def create(cpg: Cpg, vsa: ValueSetResult): TaintSinkSearcher = {
    val language = cpg.metaData.language.head
    language match {
      case Languages.PHP       => PHPTaintSinkSearcher(cpg, vsa)
      case Languages.PYTHONSRC => PythonTaintSinkSearcher(cpg, vsa)
      case _                   => throw new IllegalArgumentException(s"unsupported language: $language")
    }
  }
}

/** Trait for searching taint sinks in CPG
  */
trait TaintSinkSearcher(cpg: Cpg, vsa: ValueSetResult) {
  protected val language: String

  /** Searches for all taint sinks in the CPG.
    *
    * @return
    *   A map of vulnerability kind to their corresponding taint sinks
    */
  def search(): Map[String, List[TaintSink]] = {
    val validator                          = TaintSinkValidator.create(cpg, vsa)
    val (allFunctionCalls, allMethodCalls) = cpg.call.toList.partition(_.receiver.isEmpty)

    SourceSinkSpecManager
      .getSink(language)
      .map { case (kind, sinks) =>
        val functionCalls = searchFunctionCalls(allFunctionCalls, sinks.functions)
        val methodCalls   = searchMethodCalls(allMethodCalls, sinks.methods)

        kind -> (functionCalls ++ methodCalls).filter(sink => validator.validate(sink, kind))
      }
  }

  /** Searches for function calls that match given sink specifications.
    */
  protected def searchFunctionCalls(allFunctionCalls: List[Call], specs: List[FunCallSinkSpec]): List[TaintSink]

  /** Searches for method calls that match given sink specifications.
    */
  protected def searchMethodCalls(allMethodCalls: List[Call], specs: List[MethodCallSinkSpec]): List[TaintSink]

  /** Creates a taint sink for a given call and its arguments using the provided sink specification
    */
  protected def createTaintSink(call: Call, args: Option[Seq[Int]]): TaintSink = {
    val arguments = args match {
      case Some(indices) => indices.flatMap(call.argumentOption).toList
      case None          => call.argument.toList
    }
    CallArgumentSink(call, arguments)
  }
}

class PythonTaintSinkSearcher(cpg: Cpg, vsa: ValueSetResult) extends TaintSinkSearcher(cpg, vsa) {
  protected override val language: String = Languages.PYTHONSRC

  protected override def searchFunctionCalls(
    allFunctionCalls: List[Call],
    specs: List[FunCallSinkSpec]
  ): List[TaintSink] = List.empty

  protected override def searchMethodCalls(
    allMethodCalls: List[Call],
    specs: List[MethodCallSinkSpec]
  ): List[TaintSink] = {
    allMethodCalls.flatMap { call =>
      specs
        .find(spec =>
          spec.methodName == call.name &&
            (spec.receiverName match {
              case Some(expectedReceiver) =>
                isMatchedReceiver(call, expectedReceiver)
              case None => true
            })
        )
        .map(spec => createTaintSink(call, spec.args))
    }
  }

  /** copy from TaintSourceSearcher.scala
    */
  private def isMatchedReceiver(call: Call, pattern: String): Boolean = {
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

class PHPTaintSinkSearcher(cpg: Cpg, vsa: ValueSetResult) extends TaintSinkSearcher(cpg, vsa) {
  protected override val language: String = cpg.metaData.language.head

  protected override def searchFunctionCalls(calls: List[Call], specs: List[FunCallSinkSpec]): List[TaintSink] =
    calls.flatMap { call =>
      specs.find(_.name == call.name).map(spec => createTaintSink(call, spec.args))
    }

  protected override def searchMethodCalls(calls: List[Call], specs: List[MethodCallSinkSpec]): List[TaintSink] =
    calls.flatMap { call =>
      specs
        .find(spec =>
          spec.methodName == call.name &&
            ((spec.receiverName match {
              case Some(expectedReceiver) =>
                call.receiver.exists(_.code == expectedReceiver)
              case None => false
            }) || (spec.typeName match {
              case Some(expectedTypeName) =>
                isMatchedTypeName(call, expectedTypeName)
              case None => false
            }) || (spec.receiverName.isEmpty && spec.typeName.isEmpty))
        )
        .map(spec => createTaintSink(call, spec.args))
    }

  /** Check if the call matches the expected type name by examining callee methods
    */
  private def isMatchedTypeName(call: Call, expectedTypeName: String): Boolean = {
    call.callee(NoResolve).exists(_.astParentFullName == expectedTypeName)
  }
}
