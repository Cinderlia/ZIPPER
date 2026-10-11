package bee.zipper.core.cpgcreation

import flatgraph.DiffGraphBuilder
import io.circe.generic.auto.*
import io.circe.parser.*
import io.circe.syntax.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** dynamic function calls (e.g., call_user_func($name, $arg1, $arg2, ...)) do not always preserve a one-to-one
  * correspondence between the index of parameters and arguments. To handle this, we maintain a mapping between
  * parameters and arguments for dynamic calls. Note that one callee may correspond to multiple callsites, so each
  * callsite requires parameter-to-argument mapping.
  *
  * @param paramToArg
  *   One parameter may correspond to multiple arguments (e.g., variadic functions, __call, __callStatic).
  */
private case class DynamicCalleeTag(callsite: Call, paramToArg: Map[MethodParameterIn, List[CfgNode]])

/** @param argToParam
  *   One argument may correspond to multiple parameters (e.g., call_user_func_array($name, $args)).
  */
private case class DynamicCallsiteTag(callee: Method, argToParam: Map[CfgNode, List[MethodParameterIn]])

object DynamicCallTagger {
  def bind(
    builder: DiffGraphBuilder,
    callsite: Call,
    callee: Method,
    paramToArg: Map[MethodParameterIn, List[CfgNode]]
  ): Unit = {
    val paramToArgInt = paramToArg.map((p, as) => p.id -> as.map(a => a.id))
    CalleeTagger.bind(builder, callee, InternalCalleeTag(callsite.id, paramToArgInt))
    val argToParamInt = paramToArg.toList
      .flatMap { case (param, args) => args.map(arg => (arg, param)) }
      .groupBy(_._1)
      .map { case (arg, pairs) => arg -> pairs.map(_._2) }
      .map { case (arg, params) => arg.id() -> params.map(_.id()) }
    CallsiteTagger.bind(builder, callsite, InternalCallsiteTag(callee.id(), argToParamInt))
  }

  def hasTag(callee: Method): Boolean = CalleeTagger.hasTag(callee)

  def hasTag(callsite: Call): Boolean = CallsiteTagger.hasTag(callsite)

  def tag(cpg: Cpg, callee: Method): List[DynamicCalleeTag] = CalleeTagger
    .value(callee)
    .map(t =>
      DynamicCalleeTag(
        cpg.call.id(t.callsite).head,
        t.paramToArg.map((pId, aIds) => cpg.parameter.id(pId).head -> aIds.map(aId => cpg.cfgNode.id(aId).head))
      )
    )
    .toList

  def tag(cpg: Cpg, callsite: Call): List[DynamicCallsiteTag] = CallsiteTagger
    .value(callsite)
    .map(t =>
      DynamicCallsiteTag(
        cpg.method.id(t.callee).head,
        t.argToParam.map { case (aId, pIds) => cpg.cfgNode.id(aId).head -> pIds.map(pId => cpg.parameter.id(pId).head) }
      )
    )
    .toList

  /** The internal representation of DynamicCalleeTag to be serialized in CPG
    *
    * @param callsite
    *   The ID of the callsite node in CPG
    */
  private case class InternalCalleeTag(callsite: Long, paramToArg: Map[Long, List[Long]])

  private case class InternalCallsiteTag(callee: Long, argToParam: Map[Long, List[Long]])

  private object CallsiteTagger extends Tagger[InternalCallsiteTag] {
    override val Key: String = "DynamicCallCallsite"

    override def serialize(value: InternalCallsiteTag): String = value.asJson.noSpaces

    override def deserialize(repr: String): InternalCallsiteTag =
      decode[InternalCallsiteTag](repr).toOption.get
  }

  private object CalleeTagger extends Tagger[InternalCalleeTag] {
    override val Key: String = "DynamicCallCallee"

    override def serialize(value: InternalCalleeTag): String = value.asJson.noSpaces

    override def deserialize(repr: String): InternalCalleeTag =
      decode[InternalCalleeTag](repr).toOption.get
  }
}
