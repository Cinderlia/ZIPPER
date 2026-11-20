package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** PHP superglobals (`$_SESSION`, `$_COOKIE`, `$_SERVER`, `$GLOBALS`, ...) are process-wide containers: a value written
  * in one file is visible in every other file of the same request cycle, and for sessions even across requests.
  *
  * The CPG represents every file as its own `<global>` method, and the reaching-def analysis is ICFG based, so a
  * definition in `login.php` can never reach a use in `xss_stored_3.php`. This pass bridges that gap directly: it pairs
  * the writes of a container entry (`$_SESSION['login'] = ...`) with the reads of the same entry (`$x =
  * $_SESSION['login']`) and adds a `REACHING_DEF` edge from the written value to each read, independent of the control
  * flow graph.
  *
  * Only constant or textual entry keys are paired, so `$_SESSION[$k]` does not merge with `$_SESSION['login']`. The
  * number of reads bridged per entry is capped to keep the edge count bounded on large code bases.
  */
class SuperglobalFlowPass(cpg: Cpg, vsa: ValueSetResult) extends CpgPass(cpg) {
  import SuperglobalFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    val definitions = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]
    val uses        = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]

    cpg.call.nameExact(Operators.indexAccess).foreach { indexAccess =>
      entryKey(indexAccess) match {
        case Some(key) =>
          assignmentOf(indexAccess) match {
            case Some((_, value)) => definitions.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += value
            case None             => uses.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += indexAccess
          }
        case None =>
      }
    }

    var edges       = 0
    var skipped     = 0
    val skippedKeys = mutable.ArrayBuffer.empty[String]

    definitions.foreach { case (key, writes) =>
      uses.get(key).foreach { reads =>
        if (reads.size > maxUsesPerEntry) {
          skipped += 1
          if (skippedKeys.size < 10) skippedKeys += s"$key(${reads.size})"
        }
        val targets = reads.take(maxUsesPerEntry)
        writes.foreach { value =>
          targets.foreach { read =>
            FeatureTagger.bind(builder, read, GlobalDataDependency)
            builder.addEdge(value, read, EdgeTypes.REACHING_DEF)
            edges += 1
          }
        }
      }
    }

    logger.info(
      s"Bridged $edges superglobal value flows over ${definitions.size} written entries " +
        s"(${uses.size} read entries)"
    )
    if (skipped > 0) {
      logger.warn(
        s"$skipped superglobal entries exceed $maxUsesPerEntry reads and are bridged partially: " +
          skippedKeys.mkString(", ")
      )
    }
  }

  /** Resolve `$CONTAINER['key']` / `$GLOBALS['key']` to the entry key of the container. */
  private def entryKey(indexAccess: Call): Option[String] = {
    indexAccess.argument.l match {
      case (base: Identifier) :: rest if rest.nonEmpty && containers.contains(base.name) =>
        val index = rest.head
        val entry = vsa
          .ptsOf(indexAccess, index)
          .collectAll[StringLiteral]
          .map(_.value)
          .headOption
          .orElse(Option(index.code).filter(_.nonEmpty))
        entry.map(e => s"$$${base.name}[$e]")
      case _ =>
        None
    }
  }

  /** The assignment statement that writes the given index access, together with its value operand. */
  private def assignmentOf(indexAccess: Call): Option[(Call, CfgNode)] = {
    indexAccess.astParent match {
      case assignment: Call
          if assignment.name == Operators.assignment && assignment.argumentOption(1).exists(_.id == indexAccess.id) =>
        assignment.argumentOption(2).map(assignment -> _)
      case _ =>
        None
    }
  }
}

object SuperglobalFlowPass {

  /** PHP superglobal containers whose entries are shared by every file of the program. `GLOBALS` and the `HTTP_*_VARS`
    * aliases are included because the PHP frontend keeps them as plain identifiers.
    */
  private val containers = Set(
    "GLOBALS",
    "_SESSION",
    "_COOKIE",
    "_SERVER",
    "_ENV",
    "_FILES",
    "_REQUEST",
    "_GET",
    "_POST",
    "HTTP_SESSION_VARS",
    "HTTP_GET_VARS",
    "HTTP_POST_VARS",
    "HTTP_SERVER_VARS"
  )

  /** A single entry such as `$_SESSION['login']` can be read in hundreds of templates; capping too low silently drops
    * real use sites. The bound only guards the edge count, and every dropped read is reported in a warning.
    */
  private val maxUsesPerEntry = 5000
}
