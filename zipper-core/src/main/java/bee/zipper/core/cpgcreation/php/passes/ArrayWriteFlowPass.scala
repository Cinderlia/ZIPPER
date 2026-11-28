package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

/** Ties an array element write back to the array variable itself.
  *
  * `$args["option_value"] = $value` stores into one cell of `$args`; every later use of the whole array carries that
  * cell. PHP code that builds a payload array and hands it to a database call (`$wpdb->update($table, $args, $where)`,
  * `wp_insert_post($duplicate)`) is only reachable once this link exists.
  */
class ArrayWriteFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  private val logger = LoggerFactory.getLogger(getClass)

  private val maxUsesPerWrite = 5

  override def run(builder: DiffGraphBuilder): Unit = {
    var edges = 0
    var sites = 0

    cpg.method.ast.isCall
      .filter(_.name == Operators.assignment)
      .foreach { assignment =>
        val line = assignment.lineNumber.getOrElse(-1)
        assignment
          .argumentOption(1)
          .collect {
            case indexAccess: Call if indexAccess.name == Operators.indexAccess =>
              indexAccess
          }
          .foreach { indexAccess =>
            for {
              base <- indexAccess.argumentOption(1)
              if base.isInstanceOf[Identifier]
              arrayNode = base
              stored <- assignment.argumentOption(2)
              if line >= 0
            } {
              val arrayCode = arrayNode.code
              val uses = assignment.method.ast.isIdentifier
                .filter(_.code == arrayCode)
                .filter(_.lineNumber.exists(_ > line))
                .take(maxUsesPerWrite)
                .toList
              uses.foreach { use =>
                builder.addEdge(stored, use, EdgeTypes.REACHING_DEF)
                FeatureTagger.bind(builder, use, GlobalDataDependency)
                edges += 1
              }
              sites += 1
            }
          }
      }

    if (sites > 0) logger.info(s"Bridged $edges value flows through $sites array element writes")
  }
}
