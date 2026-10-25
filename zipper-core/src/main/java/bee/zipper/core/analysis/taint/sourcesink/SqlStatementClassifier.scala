package bee.zipper.core.analysis.taint.sourcesink

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** Coarse classification of the SQL statement a call site executes. */
enum SqlStatementKind {
  case Read, Write, Other
}

object SqlStatementKind {

  /** Parses a configuration value. `None` disables the classification filter. */
  def parse(value: Option[String]): Option[SqlStatementKind] =
    value.map(_.trim.toLowerCase).flatMap {
      case "" | "both" | "any" | "all"                 => None
      case "read" | "query" | "select"                 => Some(Read)
      case "write" | "modification" | "update" | "dml" => Some(Write)
      case _                                           => None
    }
}

/** Infers the SQL statement kind of a database call.
  *
  * The kind is normally fixed by the hard-coded part of the statement. The classifier looks at the literals reachable
  * from the call arguments, following simple local definitions, and for executor calls such as `execute()` it walks
  * back through the receiver to the `prepare(...)` that produced it.
  */
object SqlStatementClassifier {

  private val readKeywords = Set("select", "show", "describe", "explain", "pragma")
  private val writeKeywords =
    Set(
      "insert",
      "update",
      "delete",
      "replace",
      "create",
      "drop",
      "alter",
      "truncate",
      "rename",
      "upsert",
      "merge",
      "grant",
      "revoke"
    )

  private val keywordPattern =
    "(?i)(^|[^a-z])(select|show|describe|explain|pragma|insert|update|delete|replace|create|drop|alter|truncate|rename|upsert|merge|grant|revoke)".r

  /** Classifies a SQL text. A leading keyword decides the kind. */
  def classify(sql: String): Option[SqlStatementKind] =
    keywordPattern.findFirstMatchIn(sql).flatMap { m =>
      val keyword = m.group(2).toLowerCase
      if (readKeywords.contains(keyword)) Some(SqlStatementKind.Read)
      else if (writeKeywords.contains(keyword)) Some(SqlStatementKind.Write)
      else Some(SqlStatementKind.Other)
    }

  /** Best-effort SQL kind of the statement executed by `call`. */
  def kindOfCall(call: Call, depth: Int = 3): Option[SqlStatementKind] = {
    if (depth <= 0) None
    else directKind(call).orElse(receiverKind(call, depth - 1))
  }

  private def directKind(call: Call): Option[SqlStatementKind] = {
    val texts = call.argument.toList.flatMap(arg => sqlTexts(arg, 2))
    texts.flatMap(classify).headOption
  }

  /** Literal SQL fragments reachable from a node: its own literals, literals of nested calls and, for variables, the
    * literals of their nearest local definition.
    */
  private def sqlTexts(node: CfgNode, depth: Int): List[String] = {
    val literals = node.ast.collectAll[Literal].filter(_.isStr).map(_.code).toList
    if (depth <= 0) literals
    else {
      val fromVariables = node.ast
        .collectAll[Identifier]
        .toList
        .flatMap(id => definitionsOf(id).flatMap(d => sqlTexts(d, depth - 1)))
      literals ++ fromVariables
    }
  }

  private def receiverKind(call: Call, depth: Int): Option[SqlStatementKind] = {
    call.receiver.headOption.flatMap { receiver =>
      definitionsOf(receiver).flatMap {
        case c: Call => kindOfCall(c, depth)
        case other   => classify(other.code)
      }.headOption
    }
  }

  /** Nearest preceding assignment that defines the value of `node` inside the enclosing method. */
  private def definitionsOf(node: CfgNode): List[CfgNode] = {
    val code = node.code
    if (code.isEmpty) Nil
    else {
      val method = Option(node.method)
      val line   = node.lineNumber.getOrElse(-1)
      val assignments = method.toList
        .flatMap(_.ast.collectAll[Call].filter(_.isGenericAssignment).toList)
        .filter(a => a.argumentOption(1).exists(_.code == code))
        .filter(a => line < 0 || a.lineNumber.forall(_ <= line))
      assignments
        .sortBy(a => a.lineNumber.getOrElse(Int.MinValue))
        .reverse
        .headOption
        .flatMap(_.argumentOption(2))
        .toList
    }
  }
}
