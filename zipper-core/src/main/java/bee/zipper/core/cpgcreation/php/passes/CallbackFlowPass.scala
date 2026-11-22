package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

/** PHP passes functions to higher order calls such as `preg_replace_callback($pattern, [$this, 'callback'], $text)`.
  * The callback is a value, not a call: the frontend leaves the second argument of `preg_replace_callback` as an empty
  * block, so the callback body has no incoming call edge and everything inside it looks unreachable to the data flow
  * engine.
  *
  * This pass resolves those callables and reconnects them:
  *   - a `CALL` edge from the higher order call to the callback method, so the value the callback returns (the image
  *     tag built from the match, for example) is the value of the higher order call;
  *   - reaching definition edges from the subject argument to the callback parameters, so the text being processed
  *     reaches the `$matches` array the callback reads.
  *
  * Only callback names that resolve to exactly one method are bridged: the method of the class the call lives in, or a
  * single method of that name in the whole program. Ambiguous names are skipped and counted.
  */
class CallbackFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  import CallbackFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var callEdges = 0
    var dataEdges = 0
    var skipped   = 0

    cpg.call.foreach { call =>
      CallbackSpecs.get(call.name).foreach { spec =>
        resolve(call, spec) match {
          case Some(method) =>
            if (!call.method.exists(_.id == method.id)) {
              builder.addEdge(call, method, EdgeTypes.CALL)
              callEdges += 1
            }
            val params   = method.parameter.l.sortBy(_.index).take(MaxParams)
            val subjects = spec.subjectArgs.flatMap(index => call.argumentOption(index))
            val pairs =
              if (subjects.sizeIs == 1) {
                // One subject feeds all parameters of the callback: `array_reduce` hands it to both `$carry` and `$item`.
                for (subject <- subjects; parameter <- params) yield (subject, parameter)
              } else {
                subjects.zipWithIndex.flatMap { case (subject, position) => params.lift(position).map(subject -> _) }
              }
            pairs.foreach { case (subject, parameter) =>
              builder.addEdge(subject, parameter, EdgeTypes.REACHING_DEF)
              dataEdges += 1
              // A parameter node is not a statement the engine walks, so taint it into the places that read the variable.
              parameterReads(method, parameter.name).foreach { read =>
                builder.addEdge(subject, read, EdgeTypes.REACHING_DEF)
                dataEdges += 1
              }
            }
          case None => skipped += 1
        }
      }
    }

    logger.info(s"Bridged $callEdges callable calls and $dataEdges callback argument flows ($skipped unresolved)")
  }

  private def resolve(call: Call, spec: CallbackSpec): Option[Method] =
    callbackArgument(call, spec).flatMap { argument =>
      methodName(argumentCode(argument)).flatMap { name =>
        val candidates = cpg.method
          .nameExact(name)
          .filterNot(m => m.fullName.startsWith("<unresolvedNamespace>"))
          .l
        val enclosingType = enclosingMethod(call).flatMap(m => m.typeDecl.headOption).map(_.fullName)
        val sameClass =
          enclosingType.toList.flatMap(t => candidates.filter(_.typeDecl.headOption.exists(_.fullName == t)))
        if (sameClass.sizeIs == 1) sameClass.headOption
        else if (candidates.sizeIs == 1) candidates.headOption
        else None
      }
    }

  private def callbackArgument(call: Call, spec: CallbackSpec): Option[CfgNode] =
    call.argumentOption(spec.callbackArg)

  /** The identifiers that read the given parameter inside the callback body. */
  private def parameterReads(method: Method, name: String): Seq[Identifier] =
    cpg.identifier
      .nameExact(name)
      .filter(_.method.id == method.id)
      .take(MaxParameterReads)
      .l

  /** The code of the callable argument. An array literal is lowered to a synthetic block (`$tmp0[1] = "cb"`
    * assignments) whose own code is empty, so the quoted names of the descendants are collected as well.
    */
  private def argumentCode(argument: CfgNode): String = {
    val builder  = new StringBuilder(argument.code)
    var frontier = Seq(argument)
    var depth    = 0
    while (depth < 6 && frontier.nonEmpty) {
      val next = frontier.flatMap { node =>
        flatgraph.Accessors
          .getEdgesOut(node)
          .iterator
          .collect {
            case e if e.label == EdgeTypes.AST && e.dst.isInstanceOf[CfgNode] => e.dst.asInstanceOf[CfgNode]
          }
          .toSeq
      }
      next.foreach(node => builder.append(' ').append(node.code))
      frontier = next
      depth += 1
    }
    builder.toString
  }

  /** The method name denoted by a callable expression: `'name'`, `'Class::name'`, `[$this, 'name']`, `[Foo::class,
    * 'name']`.
    */
  private def methodName(code: String): Option[String] = {
    val quoted = """['"]([^'"]+)['"]""".r.findAllMatchIn(code).map(_.group(1)).toList
    quoted.reverse
      .collectFirst {
        case raw if raw.nonEmpty && !raw.startsWith("$") =>
          raw.split("::").last.trim
      }
      .map(_.stripPrefix("\\"))
      .filter(_.matches("[A-Za-z_][A-Za-z0-9_]*"))
  }

  private def enclosingMethod(node: Call): Option[Method] = {
    var current: Option[CfgNode] = Option(node.method)
    var depth                    = 0
    while (depth < 64 && current.exists(!_.isInstanceOf[Method])) {
      current = flatgraph.Accessors
        .getEdgesIn(current.get)
        .iterator
        .collectFirst {
          case e if e.label == EdgeTypes.AST && e.src.isInstanceOf[CfgNode] =>
            e.src.asInstanceOf[CfgNode]
        }
      depth += 1
    }
    current.collect { case m: Method => m }
  }
}

object CallbackFlowPass {
  private val MaxParams         = 8
  private val MaxParameterReads = 50

  /** `callbackArg` is the 1-based argument index of the callable, `subjectArgs` the arguments whose value the callback
    * derives its parameters from.
    */
  private case class CallbackSpec(callbackArg: Int, subjectArgs: Seq[Int])

  private val CallbackSpecs: Map[String, CallbackSpec] = Map(
    "preg_replace_callback" -> CallbackSpec(2, Seq(3)),
    "array_map"             -> CallbackSpec(1, 2 to 12),
    "array_filter"          -> CallbackSpec(2, Seq(1)),
    "array_walk"            -> CallbackSpec(2, Seq(1)),
    "usort"                 -> CallbackSpec(2, Seq(1)),
    "uasort"                -> CallbackSpec(2, Seq(1)),
    "uksort"                -> CallbackSpec(2, Seq(1)),
    "array_reduce"          -> CallbackSpec(2, Seq(1)),
    "call_user_func"        -> CallbackSpec(1, 2 to 12)
  )
}
