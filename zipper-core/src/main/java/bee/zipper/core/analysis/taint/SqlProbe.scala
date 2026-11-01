package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Where to put the sqlquery extension probe for a SQL call: the PHP file and line whose stack frame is expected to be
  * active when the query runs.
  */
case class SqlProbeCandidate(
  file: String,
  line: Int,
  function: String,
  code: String,
  role: String,
  score: Double,
  reasons: List[String]
)

case class SqlProbe(
  file: String,
  line: Int,
  function: String,
  code: String,
  role: String,
  score: Double,
  reasons: List[String],
  extensionConfig: Map[String, String],
  alternatives: List[SqlProbeCandidate]
)

/** Chooses the sqlquery extension probe line for one slice, without assuming any framework.
  *
  * The extension matches any frame of the userland call stack by file and line, so the ideal line is the app-level
  * callsite that dispatches this query. The selector uses structural signals only:
  *
  *   - a call whose SQL text is a literal (or built from literals in the same method) is specific to that query;
  *   - a call whose SQL text comes from a method parameter, a field, or whose method contains many SQL calls and is
  *     called from many places is a generic database layer: matching it would collect unrelated queries;
  *   - the navi middle-segment node is the anchor; if it is generic, the selector walks back along the path to the
  *     nearest specific callsite.
  */
final class SqlProbeSelector {
  private val dispatch = Set("prepare", "query", "exec", "real_query", "get_row", "get_results", "get_var", "get_col")
  private val execute  = Set("execute")

  private val sqlKeyword = """(?is)\b(select|insert|update|delete|replace|show|create|drop|alter|truncate)\b""".r

  private def fileOf(node: CfgNode): String =
    node.file.headOption.map(_.name.replace(java.io.File.separator, "/")).getOrElse("")

  private def lineOf(node: CfgNode): Int = node.lineNumber.getOrElse(-1)

  private def functionOf(call: Call): String = call.method.fullName

  private def isSqlCall(call: Call): Boolean = dispatch.contains(call.name) || execute.contains(call.name)

  private def literalSql(call: Call): Option[String] =
    call.argument.ast.collectAll[Literal].map(_.code).find(code => sqlKeyword.findFirstIn(code).isDefined)

  /** SQL text assigned to one of the call arguments in the same method. */
  private def sqlFromDefinitions(call: Call): Boolean = {
    val method = call.method
    call.argument.ast.collectAll[Identifier].exists { identifier =>
      method.ast
        .collectAll[Call]
        .filter(_.isGenericAssignment)
        .filter(assignment => assignment.argumentOption(1).exists(_.code == identifier.code))
        .exists { assignment =>
          assignment.argument.ast.collectAll[Literal].exists(literal => sqlKeyword.findFirstIn(literal.code).isDefined)
        }
    }
  }

  private def sqlFromParameter(call: Call): Boolean = {
    val method = call.method
    call.argument.ast.collectAll[Identifier].exists(identifier => method.parameter.exists(_.name == identifier.code))
  }

  private def sqlCallsInMethod(call: Call): Int =
    call.method.ast.collectAll[Call].count(candidate => isSqlCall(candidate))

  private def callsiteCount(call: Call): Int =
    try NoResolve.getMethodCallsites(call.method).size
    catch { case _: Throwable => 0 }

  /** Structural signals that the callsite belongs to a generic database layer. Script-level code (PHP files without a
    * function) is never treated as a wrapper: a page may legitimately run several queries.
    */
  private def isGenericLayer(call: Call): Boolean = {
    val method = call.method
    val script = method.name == "<global>" || method.name.startsWith("<")
    if (script) false
    else sqlFromParameter(call)
  }

  private def pathSqlLiterals(paths: List[TaintPath]): List[String] =
    paths
      .flatMap(_.path)
      .flatMap(node => node.ast.collectAll[Literal])
      .map(_.code.trim)
      .filter(literal => literal.length >= 8 && sqlKeyword.findFirstIn(literal).isDefined)
      .distinct

  private def definitionLiterals(call: Call): List[String] = {
    val method = call.method
    call.argument.ast.collectAll[Identifier].toList.flatMap { identifier =>
      method.ast
        .collectAll[Call]
        .filter(_.isGenericAssignment)
        .filter(assignment => assignment.argumentOption(1).exists(_.code == identifier.code))
        .flatMap(assignment => assignment.argument.ast.collectAll[Literal].map(_.code))
        .filter(literal => sqlKeyword.findFirstIn(literal).isDefined)
    }
  }

  private def tokens(text: String): Set[String] =
    text.toLowerCase.split("[^a-zA-Z0-9_]+").filter(_.length >= 4).toSet

  /** The candidate's SQL text shares table/column words with the SQL text of the analyzed query. */
  private def sharesQueryText(call: Call, queryLiterals: List[String]): Boolean = {
    val candidateTexts = (literalSql(call).toList ++ definitionLiterals(call)).map(_.toLowerCase)
    candidateTexts.exists { text =>
      val candidateTokens = tokens(text)
      queryLiterals.exists(query => candidateTokens.intersect(tokens(query)).size >= 2)
    }
  }

  private def score(call: Call, queryLiterals: List[String]): (Double, List[String]) = {
    val reasons = mutable.ListBuffer.empty[String]
    var value   = 0.0

    if (dispatch.contains(call.name)) {
      value += 0.35
      reasons += "query dispatch"
    } else {
      value += 0.15
      reasons += "execute call"
    }

    if (isGenericLayer(call)) {
      value -= 0.45
      reasons += "generic database layer (query text comes from callers / many call sites)"
    } else {
      value += 0.2
      reasons += "app-level callsite"
    }

    literalSql(call) match {
      case Some(literal) =>
        value += 0.25
        reasons += s"literal SQL at the callsite (${literal.take(24)})"
      case None =>
        if (sqlFromDefinitions(call)) {
          value += 0.15
          reasons += "SQL built in the same method"
        } else {
          value -= 0.2
          reasons += "dynamic/unknown SQL (may match unrelated queries)"
        }
    }

    if (queryLiterals.nonEmpty) {
      if (sharesQueryText(call, queryLiterals)) {
        value += 0.2
        reasons += "SQL text matches the analyzed query"
      } else {
        value -= 0.25
        reasons += "SQL text differs from the analyzed query (likely unrelated)"
      }
    }

    (math.max(0.0, math.min(1.0, value)), reasons.toList)
  }

  private def absolute(file: String): String = {
    val root = Option(System.getProperty("zipper.source.root"))
      .filter(_.nonEmpty)
      .map(path => if (path.endsWith("/")) path else path + "/")
    root.map(_ + file).getOrElse(file)
  }

  private def outputName(call: Call): String = {
    val base = fileOf(call).split('/').lastOption.getOrElse("query").stripSuffix(".php")
    s"result_${base}_${lineOf(call)}.json"
  }

  def select(paths: List[TaintPath]): Option[SqlProbe] = {
    val anchor     = paths.flatMap(_.middleNode).headOption
    val anchorPath = anchor.flatMap(node => paths.find(_.middleNode.exists(_.id() == node.id())))

    // Priority: the middle-segment call itself, then the callsites before it on the path, then any other SQL call.
    val ordered: List[Call] = {
      val fromPath = anchorPath
        .map { path =>
          val index  = anchor.map(node => path.path.indexWhere(_.id() == node.id())).getOrElse(-1)
          val before = if (index > 0) path.path.take(index).reverse else Nil
          (anchor.toList ++ before).collect { case call: Call if isSqlCall(call) => call }
        }
        .getOrElse(Nil)
      // If the middle node lives in a shared helper, the callsites of that helper are the app-level lines that
      // dispatch the concrete query.
      val callerCallsites = anchor.toList.flatMap {
        case call: Call =>
          try NoResolve.getMethodCallsites(call.method).collectAll[Call].take(500).toList
          catch { case _: Throwable => Nil }
        case _ => Nil
      }
      (fromPath ++ callerCallsites ++ paths.flatMap(_.path).collect { case call: Call if isSqlCall(call) => call })
        .distinctBy(call => (fileOf(call), lineOf(call)))
    }

    val queryLiterals = pathSqlLiterals(paths)
    val ranked = ordered.zipWithIndex.map { case (call, index) =>
      val (base, baseReasons) = score(call, queryLiterals)
      val isAnchor            = anchor.exists(_.id() == call.id())
      val isCaller = anchor.isDefined && !isAnchor &&
        anchorPath.exists(_.path.takeWhile(_.id() != anchor.get.id()).exists(_.id() == call.id()))
      val (bonus, contextReasons) =
        if (isAnchor) (0.1, List("navi middle segment"))
        else if (isCaller) (0.05, List("caller of the middle-segment query"))
        else (0.0, Nil)
      val candidate = SqlProbeCandidate(
        file = absolute(fileOf(call)),
        line = lineOf(call),
        function = functionOf(call),
        code = call.code.take(200),
        role = if (execute.contains(call.name)) "execute" else "dispatch",
        score = math.max(0.0, math.min(1.0, base + bonus)),
        reasons = (baseReasons ++ contextReasons).distinct
      )
      (candidate, index)
    }

    val sorted = ranked.sortBy { case (candidate, index) => (-candidate.score, index) }.map(_._1)
    sorted.headOption.map { best =>
      val calls = ordered
      SqlProbe(
        file = best.file,
        line = best.line,
        function = best.function,
        code = best.code,
        role = best.role,
        score = best.score,
        reasons = best.reasons,
        extensionConfig = Map(
          "file" -> best.file,
          "line" -> best.line.toString,
          "output" -> outputName(
            calls.find(call => absolute(fileOf(call)) == best.file && lineOf(call) == best.line).getOrElse(calls.head)
          )
        ),
        alternatives = sorted.drop(1).take(3)
      )
    }
  }
}
