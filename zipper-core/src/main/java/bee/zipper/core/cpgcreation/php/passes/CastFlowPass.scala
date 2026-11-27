package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

/** PHP type casts (`(int) $_GET['id']`, `(string) $row['name']`) are compiled to an `<operator>.cast` call whose value
  * argument carries the data. The reaching-def analysis has no rule for that operator, so any value that passes through
  * a cast loses its dependencies: `$db->query("... " . (int) $_GET['id'])` has a source, has a sink, and still shows no
  * path.
  *
  * This pass adds the missing edge from the cast operand to the cast result, so a request value keeps flowing through
  * the cast. Casts are value preserving; the casts that really sanitize an output context (`htmlspecialchars`, ...) are
  * listed as sanitizers instead, and those still cut the path in `PathFilter`.
  */
class CastFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  import CastFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var sites = 0
    var edges = 0

    cpg.call(Operators.cast).foreach { cast =>
      cast.argumentOption(2).foreach { value =>
        sites += 1
        builder.addEdge(value, cast, EdgeTypes.REACHING_DEF)
        FeatureTagger.bind(builder, value, GlobalDataDependency)
        edges += 1
      }
      // The cast itself has to behave like the operand it replaces: an expression holding a cast (`"..." . (int)
      // $_GET['id']`) gets a reaching definition from every plain operand, so the cast needs the same edge into the
      // expression that consumes it.
      cast.astParent.foreach {
        case parent: Call =>
          builder.addEdge(cast, parent, EdgeTypes.REACHING_DEF)
          edges += 1
        case _ =>
      }
    }

    if (edges > 0) logger.info(s"Bridged $edges value flows through $sites casts")
  }
}

object CastFlowPass {}
