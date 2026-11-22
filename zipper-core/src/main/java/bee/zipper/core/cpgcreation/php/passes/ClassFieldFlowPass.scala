package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.GlobalDataDependency
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** PHP objects use their fields as a data channel between methods: one method stores a value in `$this->f`, another one
  * reads it back. The reaching-def analysis is ICFG based and only propagates through call arguments and return values,
  * so a field write can never reach a field read in another method, even though both denote the same storage location.
  *
  * This pass bridges the intra-class part of that gap: for every `$this->f` it pairs the writes with the reads of the
  * same field in the same class and adds a `REACHING_DEF` edge from the written value to the read, independent of the
  * ICFG.
  *
  * The class part of the key is the declaring type, so two unrelated classes that happen to use the same field name are
  * not merged. Fields read from another class instance (`$obj->f`), inherited or trait fields, and reads inside
  * included files (which the frontend keeps as `<global>` methods without a type) are not bridged here.
  */
class ClassFieldFlowPass(cpg: Cpg) extends CpgPass(cpg) {
  import ClassFieldFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    val definitions = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]
    val uses        = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]

    cpg.call.nameExact(Operators.fieldAccess).foreach { fieldAccess =>
      fieldKey(fieldAccess).foreach { key =>
        assignmentOf(fieldAccess) match {
          case Some((_, value)) => definitions.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += value
          case None             => uses.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += fieldAccess
        }
      }
    }

    var edges       = 0
    var skipped     = 0
    val skippedKeys = mutable.ArrayBuffer.empty[String]

    definitions.foreach { case (key, writes) =>
      uses.get(key).foreach { reads =>
        if (reads.size > maxUsesPerField) {
          skipped += 1
          if (skippedKeys.size < 10) skippedKeys += s"$key(${reads.size})"
        }
        val targets = reads.take(maxUsesPerField)
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
      s"Bridged $edges class field value flows over ${definitions.size} written fields " +
        s"(${uses.size} read fields)"
    )
    if (skipped > 0) {
      logger.warn(
        s"$skipped class fields exceed $maxUsesPerField reads and are bridged partially: " + skippedKeys.mkString(", ")
      )
    }
  }

  /** `Class::$field` for a `$this->field` access inside a method of a class, `None` outside of a class. */
  private def fieldKey(fieldAccess: Call): Option[String] = {
    val field = fieldName(fieldAccess)
    val owner = ownerType(fieldAccess)
    for {
      f <- field
      t <- owner
    } yield s"${t.fullName}::$$f"
  }

  private def fieldName(fieldAccess: Call): Option[String] = {
    val raw = fieldAccess.argumentOption(2).map(_.code).getOrElse("")
    Option(raw.stripPrefix("\"").stripSuffix("\"")).filter(_.nonEmpty)
  }

  /** The type that declares the method containing the access, if the receiver is `$this`. */
  private def ownerType(fieldAccess: Call): Option[TypeDecl] = {
    val isThis = fieldAccess.argumentOption(1).exists(arg => arg.code == "$this")
    if (!isThis) return None
    Option(fieldAccess.method).flatMap(_.typeDecl.headOption)
  }

  /** The assignment statement that writes the given field access, together with its value operand. */
  private def assignmentOf(fieldAccess: Call): Option[(Call, CfgNode)] = {
    fieldAccess.astParent match {
      case assignment: Call
          if isAssignment(assignment.name) && assignment.argumentOption(1).exists(_.id == fieldAccess.id) =>
        assignment.argumentOption(2).map(assignment -> _)
      case _ =>
        None
    }
  }

  private def isAssignment(name: String): Boolean =
    name == Operators.assignment || name.startsWith("<operator>.assignment")
}

object ClassFieldFlowPass {

  /** A field may be read from many methods of the same class; the bound only guards the edge count. */
  private val maxUsesPerField = 5000
}
