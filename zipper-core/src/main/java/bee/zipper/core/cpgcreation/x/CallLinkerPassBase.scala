package bee.zipper.core.cpgcreation.x

import bee.zipper.api.solver.sym.extend.SymbolicObject
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.DynamicCall
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, ModifierTypes}
import io.shiftleft.semanticcpg.language.*
import org.slf4j.{Logger, LoggerFactory}

import scala.collection.mutable

/** Shared methods to build call graph
  */
trait CallLinkerPassBase {
  def cpg: Cpg

  def vsa: ValueSetResult

  protected val logger: Logger = LoggerFactory.getLogger(this.getClass)

  /** remove original call edges and connect to new callees.
    *
    * for unresolved callsite, joern will create an external method to represent it. we should remove it after resolve
    */
  protected def connectCallees(builder: DiffGraphBuilder, call: Call, callees: Iterable[Method]): Unit = {
    if (callees.nonEmpty) {
      call.outE(EdgeTypes.CALL).foreach(builder.removeEdge)
      FeatureTagger.bind(builder, call, DynamicCall)
    }
    callees.foreach(callee => builder.addEdge(call, callee, EdgeTypes.CALL))
  }

  protected def applyCpgDiff(builder: DiffGraphBuilder): Unit = {
    flatgraph.DiffGraphApplier.applyDiff(cpg.graph, builder)
  }

  /** Compute the pts of [[v]] at [[node]] and return the regex-style type name of the pts
    */
  protected def getObjectType(node: CfgNode, v: CfgNode): String = {
    val objs = vsa.ptsOf(node, v).collect { case obj: SymbolicObject => obj }
    getObjectType(objs)
  }

  /** Generate the regex-style type name of given objects to match typeDecl easily
    */
  protected def getObjectType(objs: Iterable[SymbolicObject]): String = {
    val typeName = {
      val typeNames = objs
        .map(_.getTypeName)
        .filterNot(x => ValueSetResult.isDotPattern(x))
      typeNames.map(x => s"($x)").mkString("|")
    }
    typeName
  }

  protected def getSubTypeDecls(typeDecl: TypeDecl): List[TypeDecl] = {
    // it seems that Joern has a bug: the _inheritsFromOut of a subclass can find the parent class,
    // but the _inheritsFromIn of the parent class cannot find the subclass.
    typeDecl :: typeDecl.referencingType
      .flatMap(typ =>
        typ._inheritsFromIn.flatMap { case subTypeDecl: TypeDecl => subTypeDecl.flatMap(getSubTypeDecls) }
      )
      .toList
  }

  protected def getSubTypeDecls(typeDeclName: String): List[TypeDecl] = {
    cpg.typeDecl(RegexEscaper.escape(typeDeclName)).flatMap(getSubTypeDecls).toList
  }

  protected def typeDeclFilter(typeDecls: List[TypeDecl], calls: List[Call]): List[TypeDecl] = {
    // FIXME: maybe infinite loop here
    def collectAllMethods(typeDecl: TypeDecl, methodNames: mutable.Set[String]): Unit = {
      methodNames.addAll(typeDecl.method.map(m => m.name.toLowerCase))
      typeDecl._inheritsFromOut.foreach { case typ: Type =>
        typ.referencedTypeDecl.foreach(parentTypeDecl => collectAllMethods(parentTypeDecl, methodNames))
      }
    }

    typeDecls.filter { typeDecl =>
      val methodNames = mutable.Set.empty[String]
      collectAllMethods(typeDecl, methodNames)
      // TODO: use calleeFilter to filter more precisely
      // Method names in PHP are case-insensitive.
      calls.forall(call => methodNames.contains(call.name.toLowerCase))
    }
  }

  protected val DefaultVisibility: Set[String] =
    Set(ModifierTypes.PRIVATE, ModifierTypes.PROTECTED, ModifierTypes.PUBLIC)

  /** @param hasReceiver
    *   true if the callsite is a method call (with a receiver object). In this case, we will filter out static methods
    *   and global functions
    * @param argSize
    *   the number of arguments at the callsite
    * @param isPartialMatchSize
    *   false if matching the argument size exactly (for example, it filters out the callee if arg size < parameter
    *   size)
    */
  protected def calleeFilter(
    hasReceiver: Boolean,
    argSize: Int,
    isPartialMatchSize: Boolean,
    modifiers: Set[String],
    candidates: List[Method]
  ): List[Method] = {
    val categoryPredicate: Method => Boolean = m => {
      // check is it a method or function ?
      val isInstanceMethod = m.parameter.exists(_.index == 0)
      // check modifier to determine the visibility of the method/function
      val hasCorrectModifier = modifiers.exists(m.modifier.modifierTypeExact(_).nonEmpty)
      (isInstanceMethod == hasReceiver) && hasCorrectModifier
    }

    val arityPredicate: Method => Boolean = m => {
      val paramSize = m.parameter.size
      if (argSize == paramSize) true                   // extract match
      else if (argSize < paramSize) isPartialMatchSize // missing arguments (maybe have default arguments)
      else false                                       // it is impossible that arg size > param size
    }

    candidates.view
      .filter(categoryPredicate)
      .filter(arityPredicate)
      .toList
  }

  protected def calleeFilter(
    hasReceiver: Boolean,
    argSize: Int,
    isPartialMatchSize: Boolean,
    candidates: List[Method]
  ): List[Method] = {
    calleeFilter(hasReceiver, argSize, isPartialMatchSize, DefaultVisibility, candidates)
  }

  protected def findMethod(typeNamePattern: String, namePattern: String): Iterator[Method] = {
    val pendingTypeNames = mutable.ArrayBuffer(typeNamePattern)
    val visitedTypeDecls = mutable.Set.empty[Long]
    val matchedMethods   = mutable.ListBuffer.empty[Method]

    try {
      while (pendingTypeNames.nonEmpty) {
        val currentTypeName = pendingTypeNames.remove(pendingTypeNames.size - 1)
        val typeDecls = cpg
          .typeDecl(RegexEscaper.escape(currentTypeName))
          .toList
          .filter(decl => visitedTypeDecls.add(decl.id()))
        val methods = typeDecls.flatMap(decl => decl.method.filter(m => ("(?i)" + namePattern).r.matches(m.name)))

        if (methods.nonEmpty) matchedMethods ++= methods
        else {
          typeDecls.reverseIterator.foreach { decl =>
            decl._inheritsFromOut.toList.reverseIterator.foreach {
              case typ: Type => pendingTypeNames += typ.name
              case _         =>
            }
          }
        }
      }
      matchedMethods.iterator
    } catch {
      case e: Exception =>
        logger.warn(s"pattern <$typeNamePattern> syntax exception")
        Iterator.empty
    }
  }

  protected def findMethod(typeNames: Set[String], methodNames: Set[String]): Iterator[Method] = {
    val namePattern = RegexEscaper.escape(methodNames.map(name => s"($name)").mkString("|"))
    typeNames.iterator.flatMap(typeName => findMethod(typeName, namePattern))
  }

  protected def findMethod(funNamePattern: String): Iterator[Method] = {
    try {
      cpg.typeDecl.flatMap(decl =>
        decl.method.filter(m => RegexEscaper.escape("(?i)" + funNamePattern).r.matches(m.name))
      )
    } catch {
      case e: Exception =>
        logger.warn(s"pattern <$funNamePattern> syntax exception")
        Iterator.empty
    }
  }

  protected def findMethod(methodNames: Set[String]): Iterator[Method] = {
    val namePattern = RegexEscaper.escape(methodNames.map(name => s"($name)").mkString("|"))
    findMethod(namePattern)
  }

  protected def findFunction(funNamePattern: String): Iterator[Method] = {
    try {
      cpg.method
        .isExternal(false)
        .filter(m => RegexEscaper.escape("(?i)" + funNamePattern).r.matches(m.name))
        .filterNot(_.fullName.contains("->"))
        .filterNot(_.fullName.contains("::"))
    } catch {
      case e: Exception =>
        logger.warn(s"pattern <$funNamePattern> syntax exception")
        Iterator.empty
    }
  }
}
