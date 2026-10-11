package bee.zipper.core.ir

import bee.zipper.api.solver.sym.term.*
import bee.zipper.util.AnyExtension.*
import io.circe.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes
import org.apache.commons.text.StringEscapeUtils

import scala.annotation.tailrec
import scala.reflect.ClassTag

object CpgNodeExtension {
  extension (node: StoredNode) {
    def isCallTo(name: String): Boolean = {
      node match {
        case call: Call if call.name == name => true
        case _                               => false
      }
    }
  }

  extension (node: AstNode) {
    @tailrec
    def getClosest[T <: AstNode: ClassTag]: Option[T] = {
      if (node.inAstMinusLeaf.nonEmpty) {
        val parent = node.astParent
        val clazz  = implicitly[ClassTag[T]].runtimeClass
        parent match {
          case t: T if clazz.isInstance(t) => Some(t)
          case _                           => parent.getClosest
        }
      } else
        None
    }

    def log: String = {
      def showCode(code: String, maxLen: Int = 25): String = {
        if (code.length <= maxLen) code
        else code.take(maxLen) + "..."
      }
      s"`${showCode(node.code)}` @ ${node.file.name.headOption.getOrElse("")}:${node.lineNumber.getOrElse(0)}"
    }
  }

  extension (call: Call) {

    /** get the sorted arguments (including receiver if it exists) of given [[call]]
      */
    def args: List[CfgNode] = call.argumentOut
      .collect { case x: Expression => x }
      .sortBy(_.argumentIndex)
      .toList

    def isCallTo(name: String): Boolean = call.name == name

    def isGenericAssignment: Boolean = call.name.contains("assignment")
  }

  extension (literal: Literal) {
    def isStr: Boolean = literal.typeFullName == "string"

    def isInt: Boolean = literal.typeFullName == "int"

    def isFloat: Boolean = literal.typeFullName == "float"

    def getString: String = StringEscapeUtils.unescapeJava(literal.code.stripPrefix("\"").stripSuffix("\""))

    def getInt: Long = {
      import java.lang.Long as JLong
      JLong.parseLong(literal.code)
    }

    def getBool: Boolean = literal.code.toLowerCase match {
      case "true"  => true
      case "false" => false
    }

    def getFloat: Float = literal.code.toFloat

    /** Parses a literal node and returns its corresponding symbolic constant value.
      */
    def toSymbol: ConstantValue = {
      literal.typeFullName match {
        case "int"    => IntLiteral(literal.getInt)
        case "string" => StringLiteral(literal.getString)
        case "bool"   => BoolLiteral(literal.getBool)
        case "null"   => IntLiteral(0)
        case "float"  => IntLiteral(literal.getFloat.toInt)
      }
    }
  }

  extension (node: CfgNode) {
    def inGenericAssignment: Iterator[OpNodes.Assignment] = {
      node._argumentIn
        .collect { case x: Call => x }
        .filter(_.name.contains("assignment"))
        .cast[OpNodes.Assignment]
    }

    def isAssignmentTarget: Boolean = {
      node match {
        case x: (Identifier | Call) =>
          x.inGenericAssignment.exists(_.target == x)
        case _ => false
      }
    }

    def line: Int = node.lineNumber.getOrElse(0)

    def filename: String = node.file.name.headOption.getOrElse("unknown")
  }

  implicit val cfgNodeEncoder: Encoder[CfgNode] = (node: CfgNode) =>
    Json.obj(
      "id"   -> Json.fromLong(node.id),
      "code" -> Json.fromString(node.code),
      "line" -> Json.fromInt(node.line),
      "file" -> Json.fromString(node.filename)
    )

  def buildCfgNodeDecoder(cpg: Cpg): Decoder[CfgNode] = (c: HCursor) =>
    for {
      id <- c.downField("id").as[Long]
      node <- cpg.graph.node(id) match {
        case n: CfgNode => Right(n)
        case _          => Left(DecodingFailure(s"id $id was not found in cpg", c.history))
      }
    } yield node
}
