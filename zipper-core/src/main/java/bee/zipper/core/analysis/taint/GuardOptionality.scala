package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Evaluates a guard under the assumption that request inputs are absent (default values). Only idioms whose default
  * behaviour is unambiguous are handled; anything else evaluates to `None` and the guard is kept.
  */
object GuardDefaultEvaluator {

  def defaultTruth(control: ControlStructure): Option[Boolean] = {
    val conditions = control.condition.l
    if (conditions.isEmpty) None else truth(conditions.head, 0)
  }

  private def stripQuotes(text: String): String =
    text.trim.stripPrefix("'").stripSuffix("'").stripPrefix("\"").stripSuffix("\"")

  private def phpTruthy(value: String): Boolean = value.nonEmpty && value != "0"

  private def literalValue(node: CfgNode): Option[String] = node match {
    case literal: Literal => Some(stripQuotes(literal.code))
    case _                => None
  }

  /** Default value of an expression when the request input is absent (empty string for superglobals and for the common
    * `isset(...) ? ... : ''` / `?? ''` idioms).
    */
  private def defaultValue(node: CfgNode, depth: Int): Option[String] = {
    if (depth > 4) return None
    node match {
      case literal: Literal                           => literalValue(literal)
      case call: Call if call.name == "get_query_var" => Some("")
      case call: Call if call.name == "<operator>.indexAccess" =>
        if (call.code.trim.startsWith("$_") || call.code.contains("$GLOBALS")) Some("") else None
      case identifier: Identifier =>
        val method = identifier.method
        val assignments = method.ast
          .collectAll[Call]
          .filter(_.isGenericAssignment)
          .filter(_.argumentOption(1).exists(_.code == identifier.code))
          .toList
        assignments.lastOption.flatMap(_.argumentOption(2)).flatMap { rhs =>
          val call = rhs.asInstanceOf[CfgNode]
          call match {
            case c: Call if c.name == "<operator>.conditional" =>
              // isset(...) ? value : default
              c.argumentOption(3).map(_.asInstanceOf[CfgNode]).flatMap(defaultValue(_, depth + 1))
            case c: Call if c.code.contains("??") =>
              c.argumentOption(2).map(_.asInstanceOf[CfgNode]).flatMap(defaultValue(_, depth + 1))
            case other => defaultValue(other, depth + 1)
          }
        }
      case _ => None
    }
  }

  private def truth(node: CfgNode, depth: Int): Option[Boolean] = {
    if (depth > 8) return None
    node match {
      case literal: Literal => Some(phpTruthy(stripQuotes(literal.code)))
      case identifier: Identifier =>
        defaultValue(identifier, depth + 1).map(phpTruthy)
      case call: Call =>
        call.name match {
          case "<operator>.logicalNot" =>
            call.argumentOption(1).map(_.asInstanceOf[CfgNode]).flatMap(truth(_, depth + 1)).map(!_)
          case "<operator>.logicalAnd" =>
            for {
              left  <- call.argumentOption(1).map(_.asInstanceOf[CfgNode]).flatMap(truth(_, depth + 1))
              right <- call.argumentOption(2).map(_.asInstanceOf[CfgNode]).flatMap(truth(_, depth + 1))
            } yield left && right
          case "<operator>.logicalOr" =>
            for {
              left  <- call.argumentOption(1).map(_.asInstanceOf[CfgNode]).flatMap(truth(_, depth + 1))
              right <- call.argumentOption(2).map(_.asInstanceOf[CfgNode]).flatMap(truth(_, depth + 1))
            } yield left || right
          case "isset" =>
            if (call.argument.exists(arg => defaultValue(arg.asInstanceOf[CfgNode], depth + 1).isDefined))
              Some(false)
            else None
          case "empty" =>
            if (call.argument.exists(arg => defaultValue(arg.asInstanceOf[CfgNode], depth + 1).isDefined))
              Some(true)
            else None
          case "get_query_var" => Some(false)
          case name if name.startsWith("is_") =>
            if (call.argument.exists(arg => defaultValue(arg.asInstanceOf[CfgNode], depth + 1).isDefined))
              Some(false)
            else None
          case "<operator>.equals" | "<operator>.identical" | "<operator>.notEquals" | "<operator>.notIdentical" =>
            val left  = call.argumentOption(1).map(_.asInstanceOf[CfgNode]).flatMap(valueOf(_, depth + 1))
            val right = call.argumentOption(2).map(_.asInstanceOf[CfgNode]).flatMap(valueOf(_, depth + 1))
            (left, right) match {
              case (Some(a), Some(b)) =>
                val equal = a == b
                Some(if (call.name.endsWith("equals") || call.name.endsWith("identical")) equal else !equal)
              case _ => None
            }
          case _ => None
        }
      case _ => None
    }
  }

  private def valueOf(node: CfgNode, depth: Int): Option[String] =
    literalValue(node).orElse(defaultValue(node, depth + 1))
}

/** Marks guards on a taint path as optional when their default (absent input) value already takes the branch used by
  * the path, then removes the guard, its condition and the provenance chain that was added for it. Dataflow nodes are
  * never removed.
  */
object GuardOptionality {
  private val logger = org.slf4j.LoggerFactory.getLogger(this.getClass)
  private val trace  = java.lang.Boolean.getBoolean("zipper.taint.traceOptional")

  def apply(path: TaintPath, provenance: TaintControlFlowProvenance): TaintPath = {
    def enclosing(node: CfgNode): List[ControlStructure] = {
      val result           = mutable.ListBuffer.empty[ControlStructure]
      val visited          = mutable.Set.empty[ControlStructure]
      var current: AstNode = node
      var closest          = current.getClosest[ControlStructure]
      while (closest.nonEmpty && visited.add(closest.get)) {
        result += closest.get
        current = closest.get
        closest = current.getClosest[ControlStructure]
      }
      result.toList
    }
    // include the enclosing `else if` chains: they are often not present as path nodes but gate the data path
    val controls =
      (path.path.collect { case control: ControlStructure => control } ++ path.path.flatMap(enclosing))
        .distinctBy(_.id())
    if (trace)
      println(s"[optional] path nodes=${path.path.size} controls=${controls.size} dataflow=${path.dataflowNodes.size}")
    if (controls.isEmpty) return path

    val dataIds = path.dataflowNodes

    case class Verdict(control: ControlStructure, optional: Boolean, removal: Set[Long], label: String)

    def takenSide(control: ControlStructure): Option[Boolean] = {
      val trueIds  = control.whenTrue.ast.map(_.id()).toSet
      val falseIds = control.whenFalse.ast.map(_.id()).toSet
      val at       = path.path.indexWhere(_.id() == control.id())
      val after    = if (at >= 0) path.path.drop(at + 1) else path.path
      val inTrue   = after.exists(node => trueIds.contains(node.id()))
      val inFalse  = after.exists(node => falseIds.contains(node.id()))
      (inTrue, inFalse) match {
        case (true, false) => Some(true)
        case (false, true) => Some(false)
        case _             => None
      }
    }

    val verdicts = controls.map { control =>
      val truth    = GuardDefaultEvaluator.defaultTruth(control)
      val taken    = takenSide(control)
      val optional = taken.exists(side => truth.contains(side))
      if (trace)
        println(
          s"[optional] ${control.file.headOption.map(_.name).getOrElse("?")}:${control.lineNumber.getOrElse(-1)} " +
            s"truth=$truth taken=$taken optional=$optional code=${control.code.linesIterator.mkString(" ").take(60)}"
        )
      val conditionIds = control.condition.ast.collectAll[CfgNode].map(_.id()).toSet
      val provenanceIds =
        if (optional) provenance.provenanceNodes(control) else Set.empty[Long]
      val removal = (conditionIds + control.id()) ++ provenanceIds
      Verdict(
        control,
        optional,
        removal,
        s"${control.file.headOption.map(_.name).getOrElse("?")}:${control.lineNumber.getOrElse(-1)} " +
          s"${control.code.linesIterator.mkString(" ").take(70)} (default value takes this branch)"
      )
    }

    val labels = verdicts.filter(_.optional).map(_.label)
    // only hide guards when the whole guard chain is satisfiable with default values; otherwise at least one input
    // is required and removing part of the constraints would make the path unsound. Optional guards are still
    // reported, so consumers know they can be omitted when the chain allows it.
    if (!verdicts.forall(_.optional)) return path.copy(optionalGuards = path.optionalGuards ++ labels)

    val removable = verdicts.flatMap(_.removal).toSet -- dataIds

    path.copy(
      path = path.path.filterNot(node => removable.contains(node.id())),
      optionalGuards = path.optionalGuards ++ labels
    )
  }
}
