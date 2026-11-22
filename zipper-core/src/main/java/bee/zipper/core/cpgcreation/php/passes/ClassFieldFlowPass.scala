package bee.zipper.core.cpgcreation.php.passes

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
  * This pass bridges that gap for `$this->f`:
  *   - always inside one class: writes and reads of the same field in the same class are paired;
  *   - with `includeGlobal`, also with the bare `$this->f` accesses inside `<global>` methods. Those are the files that
  *     PHP code `include`s at runtime while `$this` still refers to the including object (handlers and actions of a
  *     framework, for example), which the frontend keeps as a method without a declaring type. Since the receiver type
  *     is unknown there, such a field is only bridged when at most maxClassesPerGlobalField classes use a field of that
  *     name; otherwise the writes of unrelated classes would be mixed into one value.
  *
  * Fields read from another object (`$obj->f`), private fields of parent/trait declarations, and class-level reads that
  * only appear through dynamic property names are not bridged.
  */
class ClassFieldFlowPass(cpg: Cpg, includeGlobal: Boolean = false) extends CpgPass(cpg) {
  import ClassFieldFlowPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    val definitions        = mutable.Map.empty[FieldKey, mutable.ArrayBuffer[CfgNode]]
    val uses               = mutable.Map.empty[FieldKey, mutable.ArrayBuffer[CfgNode]]
    val globalDefinitions  = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]
    val globalUses         = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]
    val globalMethodFields = mutable.Map.empty[Long, mutable.Set[String]]
    val globalMethods      = mutable.Map.empty[Long, Method]

    cpg.call.nameExact(Operators.fieldAccess).foreach { fieldAccess =>
      if (isThisAccess(fieldAccess)) {
        fieldName(fieldAccess).foreach { field =>
          val write = assignmentOf(fieldAccess).map(_._2)
          // Included files are modelled as `<file>:<global>` methods that hang under a pseudo type of the same name, so
          // a `<global>` suffix means the receiver type is unknown here.
          val enclosing = enclosingMethod(fieldAccess)
          val rawOwner  = enclosing.flatMap(m => m.typeDecl.headOption).map(_.fullName)
          val isGlobal  = rawOwner.exists(_.endsWith("<global>"))
          val classOwnr = rawOwner.filterNot(_.endsWith("<global>"))

          def record(key: FieldKey): Unit = write match {
            case Some(value) => definitions.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += value
            case None        => uses.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += fieldAccess
          }

          classOwnr match {
            case Some(typeName) => record(FieldKey(typeName, field))
            case None if includeGlobal && isGlobal =>
              enclosing.foreach { m =>
                globalMethodFields.getOrElseUpdate(m.id, mutable.Set.empty[String]) += field
                globalMethods(m.id) = m
              }
              write match {
                case Some(value) => globalDefinitions.getOrElseUpdate(field, mutable.ArrayBuffer.empty) += value
                case None        => globalUses.getOrElseUpdate(field, mutable.ArrayBuffer.empty) += fieldAccess
              }
            // Without `includeGlobal`, keep the per-file pseudo type so a field written and read inside one included
            // file is still bridged.
            case None => rawOwner.foreach(pseudo => record(FieldKey(pseudo, field)))
          }
        }
      }
    }

    // A `<global>` method has no receiver type, so `$this->format(...)` inside it stays attached to an unresolved stub
    // method and the return value cannot carry taint. When the fields that method touches already name a class, those
    // calls can be resolved to the methods of that class.
    val globalCalls = mutable.Map.empty[Long, mutable.ArrayBuffer[Call]]
    if (includeGlobal) {
      cpg.call.foreach { call =>
        if (call.code.startsWith("$this->")) {
          enclosingMethod(call).filter(_.fullName.endsWith("<global>")).foreach { m =>
            globalCalls.getOrElseUpdate(m.id, mutable.ArrayBuffer.empty) += call
          }
        }
      }
    }

    var edges         = 0
    var globalEdges   = 0
    var bridgedFields = 0
    var globalFields  = 0
    var skippedWrites = 0
    var skippedReads  = 0
    var skippedGlobal = 0
    val writeKeys     = mutable.ArrayBuffer.empty[String]
    val readKeys      = mutable.ArrayBuffer.empty[String]
    val globalKeys    = mutable.ArrayBuffer.empty[String]

    def bridge(writes: scala.collection.Seq[CfgNode], reads: scala.collection.Seq[CfgNode], label: String): Int = {
      if (writes.isEmpty || reads.isEmpty) return 0
      // A field written from several places does not denote one value any more; pairing all of those writes with all
      // reads mixes unrelated data (a login check flowing into an export, for example) and mostly yields noise.
      if (writes.size > maxWritesPerField) {
        skippedWrites += 1
        if (writeKeys.size < 10) writeKeys += s"$label(${writes.size})"
        return 0
      }
      if (reads.size > maxUsesPerField) {
        skippedReads += 1
        if (readKeys.size < 10) readKeys += s"$label(${reads.size})"
      }
      var added   = 0
      val targets = reads.take(maxUsesPerField)
      writes.distinctBy(_.id).foreach { value =>
        targets.foreach { read =>
          FeatureTagger.bind(builder, read, GlobalDataDependency)
          builder.addEdge(value, read, EdgeTypes.REACHING_DEF)
          added += 1
        }
      }
      added
    }

    definitions.foreach { case (key, writes) =>
      uses.get(key).foreach { reads =>
        val added = bridge(writes, reads, key.toString)
        if (added > 0) bridgedFields += 1
        edges += added
      }
    }

    val classesByField = (definitions.keys ++ uses.keys)
      .groupBy(_.field)
      .view
      .mapValues(_.map(_.owner).toSet)
      .toMap

    if (includeGlobal && (globalUses.nonEmpty || globalDefinitions.nonEmpty)) {

      (globalUses.keySet ++ globalDefinitions.keySet).foreach { field =>
        val owners = classesByField.getOrElse(field, Set.empty)
        if (owners.isEmpty) {
          skippedGlobal += 1
          if (globalKeys.size < 10) globalKeys += s"$field(no class uses it)"
        } else if (owners.size > maxClassesPerGlobalField) {
          skippedGlobal += 1
          if (globalKeys.size < 10) globalKeys += s"$field(${owners.size} classes)"
        } else {
          var added = 0
          owners.toList.sorted.foreach { owner =>
            val key = FieldKey(owner, field)
            added = added + bridge(
              definitions.getOrElse(key, scala.collection.Seq.empty),
              globalUses.getOrElse(field, scala.collection.Seq.empty),
              s"$owner::$$$field <- <global>"
            )
            added = added + bridge(
              globalDefinitions.getOrElse(field, scala.collection.Seq.empty),
              uses.getOrElse(key, scala.collection.Seq.empty),
              s"<global> -> $owner::$$$field"
            )
          }
          added = added + bridge(
            globalDefinitions.getOrElse(field, scala.collection.Seq.empty),
            globalUses.getOrElse(field, scala.collection.Seq.empty),
            s"<global> -> <global> $field"
          )
          if (added > 0) globalFields += 1
          globalEdges = globalEdges + added
        }
      }
    }

    if (includeGlobal) {
      var typedMethods  = 0
      var resolvedCalls = 0
      globalMethodFields.foreach { case (methodId, fields) =>
        // Fields that no single class owns (`services` is a service locator used by eight classes) say nothing about the
        // receiver, so they must not block the typing of the fields that do name one class.
        val owners = fields
          .flatMap(f => classesByField.get(f).filter(_.size <= maxClassesPerGlobalField).getOrElse(Set.empty[String]))
          .toSet
        if (owners.nonEmpty && owners.size <= maxClassesPerGlobalField && globalMethods.contains(methodId)) {
          typedMethods += 1
          globalCalls.getOrElse(methodId, mutable.ArrayBuffer.empty).foreach { call =>
            val name = call.name
            if (!name.startsWith("<operator>")) {
              val targets = cpg.method
                .nameExact(name)
                .filter(m => m.typeDecl.headOption.exists(t => owners.contains(t.fullName)))
                .l
              if (targets.sizeIs == 1) {
                builder.addEdge(call, targets.head, EdgeTypes.CALL)
                resolvedCalls += 1
              }
            }
          }
        }
      }
      logger.info(s"Resolved $resolvedCalls $$this-> calls in $typedMethods <global> methods")
    }

    logger.info(
      s"Bridged $edges class field value flows over $bridgedFields of ${definitions.size} written fields " +
        s"(${uses.size} read fields)"
    )
    if (includeGlobal) {
      logger.info(s"Bridged $globalEdges class field value flows between <global> accesses and $globalFields fields")
    }
    if (skippedWrites > 0) {
      logger.warn(
        s"$skippedWrites class fields are written from more than $maxWritesPerField places and are not bridged: " +
          writeKeys.mkString(", ")
      )
    }
    if (skippedReads > 0) {
      logger.warn(
        s"$skippedReads class fields exceed $maxUsesPerField reads and are bridged partially: " + readKeys
          .mkString(", ")
      )
    }
    if (skippedGlobal > 0) {
      logger.warn(s"$skippedGlobal fields used by <global> methods are not bridged: " + globalKeys.mkString(", "))
    }
  }

  private def isThisAccess(fieldAccess: Call): Boolean =
    fieldAccess.argumentOption(1).exists(_.code == "$this")

  /** The method that contains the node. `Call.method` travels the `CONTAINS` edge, which can be absent for the nodes of
    * a `<global>` method, so fall back to walking the AST parents.
    */
  private def enclosingMethod(node: Call): Option[Method] = {
    var current: Option[CfgNode] = Option(node.method)
    var depth                    = 0
    while (depth < 64 && current.exists(!_.isInstanceOf[Method])) {
      current = flatgraph.Accessors
        .getEdgesIn(current.get)
        .iterator
        .collectFirst {
          case e if e.label == EdgeTypes.AST && e.src.isInstanceOf[CfgNode] =>
            e.src.asInstanceOf[CfgNode]
        }
      depth += 1
    }
    current.collect { case m: Method => m }
  }

  private def fieldName(fieldAccess: Call): Option[String] = {
    val raw = fieldAccess.argumentOption(2).map(_.code).getOrElse("")
    Option(raw.stripPrefix("\"").stripSuffix("\"")).filter(_.nonEmpty)
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

  private case class FieldKey(owner: String, field: String) {
    override def toString: String = s"$owner::$$$field"
  }

  /** A field may be read from many methods of the same class; the bound only guards the edge count. */
  private val maxUsesPerField = 200

  /** A field written from several places no longer carries one value; bridging those writes mixes unrelated data. */
  private val maxWritesPerField = 2

  /** `<global>` methods name no receiver type, so a field shared by many classes cannot be attributed to one of them.
    */
  private val maxClassesPerGlobalField = 3
}
