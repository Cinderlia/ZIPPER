package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

/** PHP dispatches functions by name at runtime: `call_user_func('prefix_' . $type, $args, $value)`. The name is built
  * by concatenation, so the frontend cannot resolve a callee and there is no call edge; the value handed to the
  * function therefore never reaches the parameters of the body, and whatever the body echoes stays clean.
  *
  * This pass resolves such calls when the name expression contains a literal prefix: it matches every method whose name
  * starts with that prefix, draws the call edge, and connects the remaining arguments to the parameters of each
  * resolved method (both the parameter node and the places that read the parameter, because the parameter node itself
  * is not a statement the engine walks).
  *
  * Names without a usable literal prefix (a plain variable, or a prefix shorter than [[MinPrefixLength]]) are skipped.
  */
class DynamicDispatchPass(cpg: Cpg) extends CpgPass(cpg) {
  import DynamicDispatchPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var sites      = 0
    var callEdges  = 0
    var dataEdges  = 0
    var unresolved = 0

    val methodsByName: Map[String, List[Method]] = cpg.method.nameNot(".*<lambda>.*").l.groupBy(_.name)

    cpg.call.filter(call => DispatchNames.contains(call.name)).foreach { call =>
      sites += 1
      val prefix = literalPrefix(call.argumentOption(1))
      val targets = prefix match {
        case Some(p) =>
          methodsByName.collect { case (name, ms) if name.startsWith(p) && name != p => ms }.flatten.toList
        case None => Nil
      }
      if (targets.isEmpty) {
        unresolved += 1
      } else {
        val args = call.argument.l.drop(1).sortBy(_.argumentIndex)
        targets.foreach { method =>
          if (!call.method.exists(_.id == method.id)) {
            builder.addEdge(call, method, EdgeTypes.CALL)
            callEdges += 1
          }
          val params = method.parameter.l.sortBy(_.index)
          args.zip(params).foreach { case (arg, parameter) =>
            builder.addEdge(arg, parameter, EdgeTypes.REACHING_DEF)
            dataEdges += 1
            parameterReads(method, parameter.name).foreach { read =>
              builder.addEdge(arg, read, EdgeTypes.REACHING_DEF)
              dataEdges += 1
            }
          }
        }
      }
    }

    logger.info(
      s"Bridged $dataEdges value flows through $sites dynamic dispatches ($callEdges call edges, $unresolved unresolved)"
    )
  }

  /** PHP string literals quote their value; a numeric literal must not become a prefix. */
  private def isStringLiteral(literal: Literal): Boolean = {
    val code = literal.code.trim
    code.length >= 2 && (code.head == '\'' || code.head == '"')
  }

  /** The identifiers that read the given parameter inside the method body. */
  private def parameterReads(method: Method, name: String): Seq[Identifier] =
    method.ast.isIdentifier.filter(_.name == name).l

  /** The longest literal prefix of a function-name expression, e.g. `'mtphr_metaboxer_' . $type` -> that literal. */
  private def literalPrefix(argument: Option[Expression]): Option[String] =
    argument.flatMap {
      case literal: Literal if isStringLiteral(literal) =>
        Option(literal.code.trim.stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\""))
          .filter(_.nonEmpty)
      case call: Call if ConcatOperators.contains(call.name) =>
        call.argument.l
          .sortBy(_.argumentIndex)
          .collectFirst {
            case literal: Literal if isStringLiteral(literal) =>
              literal.code.trim.stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\"")
          }
          .filter(_.length >= MinPrefixLength)
      case _ => None
    }
}

object DynamicDispatchPass {

  /** Runtime dispatch helpers whose first argument names the function to call. */
  val DispatchNames: Set[String] = Set("call_user_func", "call_user_func_array", "forward_static_call")

  /** The frontend emits PHP `.` as `<operator>.concat`; other frontends may use the generic name. */
  val ConcatOperators: Set[String] = Set("<operator>.concat", "<operator>.concatenation", "concat")

  /** A one or two character prefix would match half the program; require something specific. */
  val MinPrefixLength = 4
}
