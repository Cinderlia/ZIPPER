package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

/** `compact('option_value', 'autoload')` builds an array out of the variables named by its string arguments. The
  * frontend keeps only the string literals, so a value that reaches `$option_value` never reaches the array that is
  * handed to `$wpdb->update($table, $data, ...)`.
  *
  * This pass draws a data dependency edge from every identifier with the named variable to the `compact` call, so the
  * array carries the values of the variables it is built from. Nothing else is inferred: names without a matching
  * identifier in the same method are ignored.
  */
class CompactFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  import CompactFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var sites = 0
    var edges = 0

    cpg.method.foreach { method =>
      val identifiers = method.ast.isIdentifier.l
      method.ast.isCall.filter(call => BuilderNames.contains(call.name.toLowerCase)).foreach { call =>
        val names = call.argument.isLiteral.l.flatMap { literal =>
          val raw = literal.code.trim
          if (raw.length > 1 && (raw.head == '\'' || raw.head == '"'))
            Option(raw.substring(1, raw.length - 1).trim.stripPrefix("$")).filter(_.nonEmpty)
          else None
        }
        if (names.nonEmpty) {
          sites += 1
          names.foreach { name =>
            identifiers.filter(_.name == name).foreach { identifier =>
              builder.addEdge(identifier, call, EdgeTypes.REACHING_DEF)
              edges += 1
            }
          }
        }
      }
    }

    logger.info(s"Bridged $edges value flows through $sites array construction sites")
  }
}

object CompactFlowPass {

  /** Functions that build an array out of the variables named by their string arguments. */
  val BuilderNames: Set[String] = Set("compact")
}
