package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** The SQL text of a query is usually built in a statement of its own (`$sql = "SELECT ...";`) and only referenced by
  * the call that executes it. The query call alone therefore does not say which statement is run, which makes a
  * database-read path hard to review. This object locates that defining assignment so reports can show it next to the
  * call; it does not change the data flow.
  */
object SqlSourceContext {

  private val sqlKeyword = """(?is)\b(select|insert|update|delete|replace|show|create|drop|alter|truncate)\b""".r

  private val assignmentsByMethod = mutable.Map.empty[Long, List[Call]]

  private def assignmentsOf(method: Method): List[Call] =
    assignmentsByMethod.getOrElseUpdate(
      method.id, {
        method.ast
          .collectAll[Call]
          .filter(_.isGenericAssignment)
          .filter(assignment =>
            assignment
              .argumentOption(2)
              .exists(rhs =>
                rhs.ast.collectAll[Literal].exists(literal => sqlKeyword.findFirstIn(literal.code).isDefined)
              )
          )
          .toList
      }
    )

  /** The call that runs the query, unwrapping `$result = $link->query($sql)`. */
  private def queryCall(node: CfgNode): Option[Call] = node match {
    case call: Call if call.isGenericAssignment => call.argumentOption(2).collect { case inner: Call => inner }
    case call: Call                             => Some(call)
    case _                                      => None
  }

  /** The statement that builds the SQL string passed to `node`, when it is a separate assignment before the call. */
  def sqlDefinition(node: CfgNode): Option[CfgNode] = queryCall(node).flatMap { call =>
    val names = call.argument.ast.collectAll[Identifier].map(_.code).toSet
    if (names.isEmpty) None
    else {
      val line = call.lineNumber.getOrElse(Int.MaxValue)
      assignmentsOf(call.method)
        .filter(assignment => assignment.argumentOption(1).map(_.code).exists(names.contains))
        .filter(assignment => assignment.lineNumber.getOrElse(-1) <= line)
        .filter(assignment => assignment.id != call.id)
        .maxByOption(_.lineNumber.getOrElse(-1))
    }
  }
}
