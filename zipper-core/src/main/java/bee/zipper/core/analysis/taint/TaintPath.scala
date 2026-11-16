package bee.zipper.core.analysis.taint

import bee.zipper.core.analysis.taint.sourcesink.{SqlStatementClassifier, SqlStatementKind}
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.Path
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}

/** Represented the taint path from sink to source if `order` is true
  */
case class TaintPath(
  kind: String,
  order: Boolean,
  path: List[CfgNode],
  sinkOverride: Option[CfgNode] = None,
  unresolved: Boolean = false,
  middleNode: Option[CfgNode] = None,
  dataflowNodes: Set[Long] = Set.empty,
  optionalGuards: List[String] = Nil,
  sinkSet: List[CfgNode] = Nil
) extends Iterable[CfgNode] {
  def source: CfgNode = if (order) path.head else path.last

  /** The real sink of the path. Control-flow enhancement may append nodes after it, so the sink is recorded explicitly
    * instead of being derived from the last element.
    */
  def sink: CfgNode = sinkOverride.getOrElse(if (order) path.last else path.head)

  /** Path up to (and including) the sink; trailing enhancement nodes are dropped. */
  def trimmed: TaintPath = {
    val index = path.indexWhere(_.id() == sink.id())
    if (index >= 0 && index < path.size - 1) copy(path = path.take(index + 1)) else this
  }

  override def iterator: Iterator[CfgNode] = path.iterator

  def prettyPrint: String = {
    Path.show.apply(Path(path))
  }
}

object TaintPathFilters {
  // Numeric conversion yields a numeric scalar, which is inert when rendered in any XSS output context.
  // Context-specific HTML/URL encoders are deliberately excluded from this reliability set.
  private val reliableXssValueFilters = Set("intval", "floatval", "doubleval")

  def isReliableXssValueFilter(name: String): Boolean = reliableXssValueFilters.contains(name.toLowerCase)

  private val reviewOnlyXssEncoders = Set("htmlspecialchars", "htmlentities", "strip_tags", "rawurlencode", "urlencode")

  /** Encoders recognized on-path when they consume a value already on the source-to-sink path. */
  def deprioritizingXssSanitizers(path: TaintPath): List[String] = {
    val nodes = path.trimmed.path
    nodes.zipWithIndex
      .collect {
        case (call: Call, callIndex)
            if (reliableXssValueFilters.contains(call.name.toLowerCase) ||
              reviewOnlyXssEncoders.contains(call.name.toLowerCase)) &&
              call.argument.l.exists(arg => nodes.take(callIndex).exists(_.id() == arg.id())) =>
          call.name.toLowerCase
      }
      .distinct
      .sorted
  }

  def hasDeprioritizingXssSanitizer(path: TaintPath): Boolean =
    deprioritizingXssSanitizers(path).nonEmpty

  private val databaseReadNames = Set(
    "mysql_fetch_array",
    "mysqli_fetch_array",
    "mysql_fetch_assoc",
    "mysqli_fetch_assoc",
    "mysql_fetch_row",
    "mysqli_fetch_row",
    "mysql_fetch_object",
    "mysqli_fetch_object",
    "fetch",
    "fetchall",
    "fetch_assoc",
    "fetch_row",
    "fetch_array",
    "fetch_object",
    "fetchcolumn",
    "get_row",
    "get_results",
    "get_var",
    "get_col"
  )

  /** A query-result-to-output relation is indirect for the once-request-to-sink scenarios. */
  def isDatabaseMediatedRequestFlow(path: TaintPath): Boolean = {
    val nodes = path.trimmed.path
    val queryRead = nodes.exists {
      case call: Call => SqlStatementClassifier.kindOfCall(call).contains(SqlStatementKind.Read)
      case _          => false
    }
    val rowFetch = nodes.exists {
      case call: Call => databaseReadNames.contains(call.name.toLowerCase)
      case _          => false
    }
    queryRead && rowFetch
  }

  def isDatabaseMediatedRequestXss(path: TaintPath): Boolean =
    path.kind.equalsIgnoreCase("Xss") && isDatabaseMediatedRequestFlow(path)
}
