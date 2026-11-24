package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** PHP `extract($row)` turns the entries of an array into local variables: `$aRow = mysqli_fetch_array($rs)` followed
  * by `extract($aRow)` makes every column of the fetched row readable as a plain variable (`$per_Facebook`, `$sState`,
  * ...).
  *
  * The keys of a database row are only known at run time, so the frontend cannot create the local variables and the
  * reaching-def analysis has no edge from the fetched row to the variables the page prints. This pass bridges that gap
  * for the pattern the compiler cannot resolve, with two deliberate restrictions that keep the added edges close to
  * real data flow:
  *
  *   - only arrays whose value is a database row are bridged, i.e. the extracted value is a row producing call
  *     (`mysqli_fetch_array`, `PDOStatement::fetch`, `fetch_assoc`, ...) or a variable assigned from one. A project
  *     that `extract`s request data or configuration into the scope is left alone;
  *   - a variable is skipped when the method defines it on its own path: a parameter, or an assignment that precedes
  *     the use (`$name = $_POST['name']`, `$name = legacyFilterInput(...)`). Then extract is no longer the value the
  *     page prints.
  *
  * The pass is opt-in (`--enable-extract-flow`): the row keys are unknown, so every bridged variable is a guess that
  * the row contains a column of that name.
  */
class ExtractFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  import ExtractFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var sites         = 0
    var edges         = 0
    var ignoredArrays = 0
    var keptVariables = 0

    cpg.method.foreach { method =>
      val calls    = method.ast.isCall.l
      val extracts = calls.filter(call => call.name == "extract" && call.receiver.isEmpty)
      if (extracts.nonEmpty) {
        val rowSources  = sqlRowSources(calls)
        val defs        = definitions(method, calls)
        val identifiers = method.ast.isIdentifier.l
        extracts.foreach { extractCall =>
          val sources = extractArgument(extractCall, rowSources)
          sources match {
            case Some(rowCalls) =>
              sites += 1
              val targets = reachableVariables(extractCall, identifiers, defs)
              keptVariables += targets.size
              for {
                source <- rowCalls
                target <- targets
              } {
                FeatureTagger.bind(builder, target, GlobalDataDependency)
                builder.addEdge(source, target, EdgeTypes.REACHING_DEF)
                edges += 1
              }
            case None => ignoredArrays += 1
          }
        }
      }
    }

    logger.info(
      s"Bridged $edges extract() flows over $sites row extractions ($keptVariables variables, " +
        s"$ignoredArrays extract sites ignored as non-row arrays)"
    )
  }

  /** The row producing calls behind the extracted value: `extract(mysqli_fetch_array($rs))` directly, or
    * `extract($aRow)` where `$aRow` is assigned from such a call.
    */
  private def extractArgument(extractCall: Call, rowSources: Map[String, List[Call]]): Option[List[Call]] =
    extractCall.argumentOption(1) match {
      case Some(call: Call) if isSqlRowProducer(call) => Some(List(call))
      case Some(id: Identifier)                       => rowSources.get(id.name)
      case _                                          => None
    }

  /** Map a variable name to the row producing calls that assign it, following one level of simple aliasing. */
  private def sqlRowSources(calls: List[Call]): Map[String, List[Call]] = {
    val direct  = mutable.Map.empty[String, mutable.ArrayBuffer[Call]]
    val aliases = mutable.ArrayBuffer.empty[(String, String)]

    calls.filter(_.name == Operators.assignment).foreach { assignment =>
      val name = assignment.argumentOption(1).collect { case id: Identifier => id.name }
      name.foreach { target =>
        assignment.argumentOption(2).foreach {
          case call: Call if isSqlRowProducer(call) =>
            direct.getOrElseUpdate(target, mutable.ArrayBuffer.empty) += call
          case source: Identifier => aliases += target -> source.name
          case _                  =>
        }
      }
    }

    aliases.foreach { case (target, source) =>
      direct.get(source).foreach(values => direct.getOrElseUpdate(target, mutable.ArrayBuffer.empty) ++= values)
    }

    direct.view.mapValues(_.toList).toMap
  }

  /** Names the method defines itself and the line each definition sits on; a parameter blocks the whole method. */
  private def definitions(method: Method, calls: List[Call]): Map[String, List[Int]] = {
    val defs = mutable.Map.empty[String, mutable.ArrayBuffer[Int]]

    method.parameter.name.foreach(name => defs.getOrElseUpdate(name, mutable.ArrayBuffer.empty) += -1)
    calls.filter(_.name == Operators.assignment).foreach { assignment =>
      val line = assignment.lineNumber.getOrElse(-1)
      assignment.argumentOption(1).foreach { lhs =>
        lhs.ast.isIdentifier.name.foreach(name => defs.getOrElseUpdate(name, mutable.ArrayBuffer.empty) += line)
      }
    }

    defs.view.mapValues(_.toList).toMap
  }

  /** Identifiers that the extraction can define, capped to keep the edge count bounded.
    *
    * The walk is by line number rather than by CFG edge: a PHP file is compiled into one `<global>` method whose
    * control flow is cut at every `?> ... <?php` boundary, so the code that prints an extracted variable is frequently
    * not CFG reachable from the `extract` call that defines it, although both live in the same file scope.
    */
  private def reachableVariables(
    extractCall: Call,
    identifiers: List[Identifier],
    defs: Map[String, List[Int]]
  ): List[Identifier] = {
    val extractionLine = extractCall.lineNumber.getOrElse(-1)
    identifiers
      .filter(id => isBridgeableName(id.name))
      .filter(id => id.lineNumber.exists(line => extractionLine < 0 || line > extractionLine))
      .filterNot(id => redefinedBefore(id, defs))
      .take(maxTargetsPerSite)
  }

  /** A parameter, or an assignment that is not after the use, makes the variable something else than the row entry. */
  private def redefinedBefore(identifier: Identifier, defs: Map[String, List[Int]]): Boolean =
    defs.get(identifier.name) match {
      case None => false
      case Some(lines) =>
        val use = identifier.lineNumber.getOrElse(-1)
        lines.exists(line => line < 0 || use < 0 || line <= use)
    }
}

object ExtractFlowPass {

  /** Calls that return a database row (or a list of rows) read from a query result. */
  private val SqlRowProducers: Set[String] = Set(
    "mysqli_fetch_array",
    "mysqli_fetch_assoc",
    "mysqli_fetch_row",
    "mysqli_fetch_object",
    "mysql_fetch_array",
    "mysql_fetch_assoc",
    "mysql_fetch_row",
    "mysql_fetch_object",
    "pg_fetch_array",
    "pg_fetch_assoc",
    "pg_fetch_row",
    "pg_fetch_object",
    "pg_fetch_all",
    "sqlsrv_fetch_array",
    "sqlsrv_fetch_object",
    "sqlite_fetch_array",
    "oci_fetch_array",
    "oci_fetch_assoc",
    "odbc_fetch_array",
    "fetch_assoc",
    "fetch_array",
    "fetch_row",
    "fetch_object",
    "fetchall",
    "fetch"
  )

  private val maxTargetsPerSite = 300

  private def isSqlRowProducer(call: Call): Boolean =
    SqlRowProducers.contains(call.name.toLowerCase)

  private def isBridgeableName(name: String): Boolean = {
    val head = name.head
    name.nonEmpty && (head == '_' || head.isLetter) && !builtins.contains(name)
  }

  private val builtins: Set[String] = Set("this", "GLOBALS")
}
