package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.extend.{SymbolicArray, SymbolicObject}
import bee.zipper.api.solver.sym.term.{StringLiteral, SymbolicValue}
import bee.zipper.core.analysis.taint.InputStructureTag
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.DynamicCallTagger
import bee.zipper.core.cpgcreation.x.RegexEscaper
import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}

import scala.collection.mutable
import scala.util.control.Breaks.*

object IterativeDynamicCallLayer {
  def run(
    cpg: Cpg,
    vsa: ValueSetResult,
    enhanced: Boolean = true,
    fixJoernCallGraph: Boolean = false,
    iterations: Option[Int] = Some(1)
  ): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new IterativeDynamicCallLayer(vsa, enhanced, fixJoernCallGraph, iterations)
    layer.run(context)
  }
}

private class IterativeDynamicCallLayer(
  vsa: ValueSetResult,
  enhanced: Boolean,
  fixJoernCallGraph: Boolean,
  iterations: Option[Int]
) extends LayerCreator {
  override val overlayName: String = "IterativeDynamicCallPass"

  override val description: String = "Resolve php dynamic calls in an iterative way"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new IterativeDynamicCallPass(cpg, vsa, enhanced, fixJoernCallGraph, iterations)
    pass.createAndApply()
  }
}

private enum DynCallKind {
  case FileInclusion, VariableCall, VariableMethodCall, StaticVariableMethodCall, VariableNew, CallUserFunc,
    CallUserFuncArray, MethodCall, StaticMethodCall, FunctionCall, NonDynCall
}

private object DynCallKind {
  def getKind(call: Call): DynCallKind = call match {
    case _ if isFileInclude(call)              => FileInclusion
    case _ if isVariableCall(call)             => VariableCall
    case _ if isVariableMethodCall(call)       => VariableMethodCall
    case _ if isStaticVariableMethodCall(call) => StaticVariableMethodCall
    case _ if isVariableNew(call)              => VariableNew
    case _ if isCallUserFunc(call)             => CallUserFunc
    case _ if isCallUserFuncArray(call)        => CallUserFuncArray
    case _ if isMethodCall(call)               => MethodCall
    case _ if isStaticMethodCall(call)         => StaticMethodCall
    case _ if isFunctionCall(call)             => FunctionCall
    case _                                     => NonDynCall
  }

  private val includeFunNames     = List("include", "require", "include_once", "require_once").mkString("|")
  private val methodCallBlackList = Set("key", "current", "next", "rewind", "valid") // method names of Iterator

  private def isStandardCall(call: Call): Boolean = {
    !call.name.contains("$") && !methodCallBlackList.contains(call.name)
  }

  def isFileInclude(call: Call): Boolean = {
    call.name.matches(includeFunNames)
  }

  def isVariableCall(call: Call): Boolean = {
    // $name() =>
    //     methodFullName = "$name"
    //     receiver = [Identifier("$name")]
    //     name = "$name"
    //     args = [Identifier("$name")]
    val isRightReceiver = call.receiver.headOption match {
      case Some(id: Identifier) if call.name.contains("$") => true // identifier
      case Some(block: Block) if call.name.isEmpty         => true // array/object
      case _                                               => false
    }
    isRightReceiver && !call.methodFullName.contains("::")
  }

  def isStaticVariableMethodCall(call: Call): Boolean = {
    // MyClass::$name()
    //     methodFullName = "MyClass::$name"
    //     receiver = [Identifier("$name")]
    //     name = "$name"
    //     args = [Identifier("$name")]
    val isIdentifierReceiver = call.receiver.headOption match {
      case Some(id: Identifier) => true
      case _                    => false
    }
    isIdentifierReceiver && call.methodFullName.contains("::") && call.name.contains("$")
  }

  def isStaticMethodCall(call: Call): Boolean = {
    call.receiver.isEmpty && call.methodFullName.contains("::") && isStandardCall(call)
  }

  def isVariableMethodCall(call: Call): Boolean = {
    // getObj()->$name()
    //     receiver = [operator.fieldAccess(getObj(), $name)]
    //     name = "$name"
    //     args = [operator.fieldAccess(getObj(), $name)]
    val isFieldAccessReceiver = call.receiver.headOption match {
      case Some(c: Call) => c.name == Operators.fieldAccess
      case _             => false
    }
    isFieldAccessReceiver && call.name.contains("$")
  }

  def isVariableNew(call: Call): Boolean = {
    call.name == Operators.alloc && call.typeFullName.contains("$")
  }

  def isCallUserFunc(call: Call): Boolean = call.name == "call_user_func"

  def isCallUserFuncArray(call: Call): Boolean = call.name == "call_user_func_array"

  def isMethodCall(call: Call): Boolean = {
    call.receiver.nonEmpty && isStandardCall(call)
  }

  def isFunctionCall(call: Call): Boolean = {
    call.receiver.isEmpty && isStandardCall(call)
  }
}

/** @param enhanced
  *   false indicates using TChecker-style algorithm, in which case we will disable 1) constraints collections for .*
  *   pattern and 2) array-style callable and 3) method call with receiver evaluated failure and 4) call_user_func_xxx
  *   and 5) fuzzy matching in file inclusion 6) CHA-analysis for unresolved this calls
  * @param fixJoernCallGraph
  *   the call graph for function call in method body may be not correct in Joern, so we need to fix it. Currently, it
  *   will introduce many false positives, so we add a flag to control it.
  */
class IterativeDynamicCallPass(
  val cpg: Cpg,
  val vsa: ValueSetResult,
  val enhanced: Boolean,
  fixJoernCallGraph: Boolean,
  iterations: Option[Int]
) extends CpgPass(cpg),
      PhpCallLinkerPassBase {
  override def run(builder: DiffGraphBuilder): Unit = solve()

  /** callsite has been resolved but can be more precise in future iteration
    */
  private val unstableCalls = mutable.Set.empty[Call]

  /** Resolve dynamic calls iteratively
    */
  private def solve(): Unit = {
    val worklist       = initWorkList()
    var iterationCount = 0
    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      logger.info(s"The ${iterationCount + 1}th iteration for resolving php dynamic calls")
      val builder            = Cpg.newDiffGraphBuilder
      val emptyReceiverCalls = mutable.ListBuffer.empty[Call]
      val resolvedCallees    = mutable.Set.empty[Method]
      val size               = worklist.size
      for (i <- 0 until size) {
        val (call, kind) = worklist.dequeue()
        val callees = kind match {
          case DynCallKind.NonDynCall               => List.empty
          case DynCallKind.FileInclusion            => forFileInclusion(call, builder)
          case DynCallKind.VariableCall             => forVariableCall(call, builder)
          case DynCallKind.StaticVariableMethodCall => forStaticVariableMethodCall(call, builder)
          case DynCallKind.VariableMethodCall       => forVariableMethodCall(call, builder)
          case DynCallKind.VariableNew              => forVariableNew(call, builder)
          case DynCallKind.StaticMethodCall         => forStaticMethodCall(call, builder)
          case DynCallKind.CallUserFunc =>
            if (enhanced) forCallUserFuncFamily(call, false, builder)
            else List.empty
          case DynCallKind.CallUserFuncArray =>
            if (enhanced) forCallUserFuncFamily(call, true, builder)
            else List.empty
          case DynCallKind.MethodCall =>
            val (isEmptyReceiver, callees) = forMethodCall(call, builder)
            if (isEmptyReceiver)
              emptyReceiverCalls += call
            callees
          case DynCallKind.FunctionCall =>
            if (fixJoernCallGraph) forFunctionCall(call, builder)
            else List.empty
        }
        resolvedCallees ++= callees
      }
      if (enhanced)
        resolvedCallees ++= forEmptyReceiverCall(emptyReceiverCalls, calleeThreshold = 5, builder)
      logger.info(s"${resolvedCallees.size} new callees are resolved")
      // apply the changes to CPG
      applyCpgDiff(builder)
      // add unresolved calls in new callees to worklist (because new callees will introduce new dataflow edges)
      val unresolvedCalls =
        resolvedCallees
          .flatMap(getUnresolvedCalls)
          .map(call => (call, DynCallKind.getKind(call)))
      worklist ++= unresolvedCalls
      // clean the VSA cache
      vsa.clear()
      iterationCount += 1
    }
  }

  private def initWorkList(): mutable.Queue[(Call, DynCallKind)] = {
    val worklist = mutable.Queue.empty[(Call, DynCallKind)]

    def isInterestingFunCall(call: Call): Boolean = {
      val callees = call.callOut.toList

      val isInterestingTarget =
        // unresolved function call
        callees.exists(_.isExternal)
        // where method calls can sometimes be resolved as function calls. see https://github.com/joernio/joern/issues/3050
          || callees.exists(_.fullName.contains("->"))
          || callees.exists(_.fullName.contains("::"))

      isInterestingTarget && isUserDefinedCall(call)
    }

    def isInterestingMethodCall(call: Call): Boolean = {
      call.callOut.exists(_.isExternal)
    }

    cpg.call.foreach { call =>
      val kind = DynCallKind.getKind(call)
      val shouldBeAdded = kind match {
        case DynCallKind.MethodCall | DynCallKind.StaticMethodCall => isInterestingMethodCall(call)
        case DynCallKind.FunctionCall                              => isInterestingFunCall(call)
        case _                                                     => true
      }
      if (shouldBeAdded) {
        worklist += ((call, kind))
      }
    }
    worklist
  }

  private val mToUserDefinedCalls = mutable.Map.empty[Method, List[Call]]

  private def isUserDefinedCall(c: Call): Boolean = {
    !c.name.startsWith("<operator") && !PhpBuiltins.FuncNames.contains(c.name)
  }

  private def getUnresolvedCalls(method: Method): List[Call] = {
    def isUnresolvedCall(c: Call): Boolean = {
      val callees = NoResolve.getCalledMethods(c)
      callees.isEmpty || callees.exists(_.isExternal) || unstableCalls.contains(c)
    }

    val userDefinedCalls =
      mToUserDefinedCalls.getOrElseUpdate(method, method.cfgNode.isCall.filter(isUserDefinedCall).toList)

    userDefinedCalls.filter(isUnresolvedCall)
  }

  private def forFileInclusion(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    def buildFuzzyFileName(rawFileName: String): String = {
      def findFileSeparator(rawFileName: String): Option[String] = {
        rawFileName match {
          case s if s.contains("/")  => Some("/")
          case s if s.contains("\\") => Some("\\")
          case _                     => None
        }
      }
      val opt = findFileSeparator(rawFileName)
      opt match {
        case Some(sep) =>
          val components = rawFileName.split(sep).reverse
          val subPath =
            if (enhanced) components.takeWhile(c => c != ".." && c != ".").reverse
            else components.reverse
          subPath.mkString(java.io.File.separator) // change to the representation in joern
        case None => rawFileName
      }
    }

    def findMatchedFile(fileNamePattern: String): List[Method] = {
      if (ValueSetResult.isDotPattern(fileNamePattern)) List.empty
      else {
        try {
          val regex =
            if (enhanced) ("^.*" + RegexEscaper.escape(fileNamePattern) + "$").r // ends with this pattern
            else RegexEscaper.escape(fileNamePattern).r
          val files   = cpg.file.filter(file => regex.matches(file.name))
          val methods = files.method.filter(_.name == "<global>").toList
          methods
        } catch {
          case e: Exception =>
            logger.warn(s"pattern <$fileNamePattern> syntax exception")
            List.empty
        }
      }
    }

    logger.info(s"Resolve file inclusion ${call.log}")
    call.argumentOption(1) match {
      case None => List.empty
      case Some(fileNameNode) =>
        val callees = vsa
          .ptsOf(call, fileNameNode, partialEval = true)
          .collect { case s: StringLiteral => s.value }
          .map(buildFuzzyFileName)
          .flatMap(findMatchedFile)
        connectCallees(builder, call, callees)
        callees
    }
  }

  private def forVariableCall(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    // $name() =>
    //     receiver = [Identifier("$name")]
    //     name = "$name"
    //     args = [Identifier("$name")]
    logger.info(s"Resolve variable call ${call.log}")
    call.receiver.headOption match {
      case Some(receiver) =>
        val pts       = vsa.ptsOf(call, receiver, partialEval = true)
        val argSize   = call.args.size
        val arguments = call.args.tail.map(_.code)
        val callees = pts
          .map(callable => resolveCallable(call, receiver, callable, enhanced, Some(arguments)))
          .groupBy(_._2)
          .flatMap { case (kind, pair) =>
            val rawCallees = pair.flatMap(_._1).toList
            val callees = kind match {
              case CallableKind.String =>
                calleeFilter(hasReceiver = false, argSize - 1, false, Set(ModifierTypes.PUBLIC), rawCallees)
              case CallableKind.Object =>
                calleeFilter(hasReceiver = true, argSize, false, Set(ModifierTypes.PUBLIC), rawCallees)
              case _ => rawCallees
            }
            callees
          }
        connectCallees(builder, call, callees)
        callees
      case None => List.empty
    }
  }

  // Rules to resolve method calls:
  //   - [Extract Matching]: the method name and the type of receiver can be inferred through VSA (not .* pattern), in this case, we
  //     just match and filter them by parameter size
  //       - [Extract Matching (Artemis)]: the method name can't be found in class definition, we connect it to magic methods (__call and __callStatic)
  //   - [Heuristic Matching]: the method name or the type of receiver cannot be inferred precisely through VSA, those methods with same
  //     parameter size with arguments are considered as candidate callees, and we use heuristic rules (heuristicCalleeFilter) to filter them.

  private def forStaticVariableMethodCall(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    // MyClass::$name()
    //     methodFullName = "MyClass::$name"
    //     receiver = [Identifier("$name")]
    //     name = "$name"
    //     args = [Identifier("$name")]
    logger.info(s"Resolve static variable method call ${call.log}")
    // Example: For a call `MyClass::$methodName()`, typeName is "MyClass"
    val scopeExp = splitOnLast(call.methodFullName, "::").head
    call.receiver.headOption match {
      case Some(methodNameIdentifier: Identifier) =>
        val potentialTypeName = resolveScopeExp(cpg, call, scopeExp)
        val potentialMethodNames =
          vsa
            .ptsOf(call, methodNameIdentifier, partialEval = true)
            .collect { case s: StringLiteral => s.value }
            .filterNot(ValueSetResult.isDotPattern)
        val resolvedCallees =
          if (potentialTypeName.nonEmpty && potentialMethodNames.nonEmpty) {
            // [Extract Matching]
            logger.info("[Extract Matching] method names: " + potentialMethodNames.mkString(", "))
            val exactMatching = calleeFilter(
              hasReceiver = false,
              call.argument.size - 1,
              false,
              Set(ModifierTypes.PUBLIC),
              findMethod(Set(scopeExp), potentialMethodNames).toList
            )
            if (exactMatching.nonEmpty) exactMatching
            else {
              // [Extract Matching (Artemis)]
              logger.info(s"[Extract Matching (Artemis)] try to connect to __callStatic method")
              val magicMethods = findMethod(scopeExp, "__callStatic").toList
              connectMagicMethods(builder, call, magicMethods)
              // magic methods don't need parameter/argument size filtering
              magicMethods
            }
          } else {
            // [Heuristic Matching]
            logger.info(
              "[Heuristic Matching] VSA fails to infer type/method names. Try to match callees by heuristic rules"
            )
            val initialCandidates = if (potentialTypeName.nonEmpty) {
              val typeDecls = getSubTypeDecls(potentialTypeName.get)
              typeDecls.method.toList
            } else if (potentialMethodNames.nonEmpty) {
              findMethod(potentialMethodNames).toList
            } else {
              // typeName and methodName are both unknown (.* pattern)
              cpg.method.toList
            }
            val arguments = call.argument.toList.tail.map(_.code) // exclude the fake receiver
            heuristicCalleeFilter(
              call,
              calleeFilter(
                hasReceiver = false,
                call.argument.size - 1,
                false,
                Set(ModifierTypes.PUBLIC),
                initialCandidates
              ),
              Some(arguments)
            )
          }
        connectCallees(builder, call, resolvedCallees)
        resolvedCallees
      case _ => List.empty
    }
  }

  private def connectMagicMethods(
    builder: DiffGraphBuilder,
    call: Call,
    magicMethods: List[Method],
    hasFakeReceiver: Boolean = true
  ): Unit = {
    magicMethods.foreach(magicMethod =>
      logger.info(s"connect to magic method ${magicMethod.fullName}")
      val arguments = if (hasFakeReceiver) call.argument.toList.tail else call.argument.toList
      // static function __callStatic($method, $params=[]) or function __call($method, $params=[])
      // get the $params parameter
      val paramsParameter = magicMethod.parameter.last
      val paramToArg      = Map(paramsParameter -> arguments)
      DynamicCallTagger.bind(builder, call, magicMethod, paramToArg)
    )
  }

  private def splitOnLast(str: String, delimiter: String): (String, String) = {
    val lastIndex = str.lastIndexOf(delimiter)
    if (lastIndex == -1) (str, "")
    else {
      val part1 = str.substring(0, lastIndex)
      val part2 = str.substring(lastIndex + delimiter.length)
      (part1, part2)
    }
  }

  /** resolve the type for a given scope expression connected by `::` operator, like `self::$obj::$member`
    */
  private def resolveScopeExp(cpg: Cpg, ctx: Call, prefix: String): Option[String] = {
    prefix match {
      case "self" | "$this" =>
        ctx.getClosest[TypeDecl].map(_.name)
      case x if x.contains("::") =>
        // currently not supported by joern
        None
      case x =>
        if (cpg.typeDecl(RegexEscaper.escape(prefix)).nonEmpty) Some(prefix)
        else None
    }
  }

  private def forStaticMethodCall(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Resolve static method call ${call.log}")
    val methodName        = call.name
    val scopeExp          = splitOnLast(call.methodFullName, "::").head
    val potentialTypeName = resolveScopeExp(cpg, call, scopeExp)
    val resolvedCallees = if (potentialTypeName.nonEmpty) {
      logger.info(s"[Extract Matching] receiver type: ${potentialTypeName.get}")
      val exactMatching = calleeFilter(
        hasReceiver = false,
        call.argument.size,
        isPartialMatchSize = false,
        Set(ModifierTypes.PUBLIC),
        findMethod(scopeExp, methodName).toList
      )
      if (exactMatching.nonEmpty) exactMatching
      else {
        logger.info(s"[Extract Matching (Artemis)] try to connect to __callStatic method")
        val magicMethods = findMethod(scopeExp, "__callStatic").toList
        connectMagicMethods(builder, call, magicMethods, hasFakeReceiver = false)
        magicMethods
      }
    } else {
      logger.info("[Heuristic Matching] VSA fails to infer receiver type. Try to match callees by heuristic rules")
      val initialCandidates = cpg.method.toList
      val arguments         = call.argument.toList.map(_.code)
      heuristicCalleeFilter(
        call,
        calleeFilter(
          hasReceiver = false,
          call.argument.size,
          isPartialMatchSize = false,
          Set(ModifierTypes.PUBLIC),
          initialCandidates
        ),
        Some(arguments)
      )
    }
    connectCallees(builder, call, resolvedCallees)
    resolvedCallees
  }

  private def forVariableMethodCall(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    // $this->$name()
    //     receiver = [operator.fieldAccess($this, $name)]
    //     name = "$name"
    //     args = [operator.fieldAccess($this, $name)]
    // getObj()->$name()
    //     receiver = [operator.fieldAccess(getObj(), $name)]
    //     name = "$name"
    //     args = [operator.fieldAccess(getObj(), $name)]

    logger.info(s"Resolve variable method call ${call.log}")
    call.receiver.headOption match {
      case Some(receiver: Call) if receiver.name == Operators.fieldAccess =>
        receiver.argument.toList match {
          case List(obj, methodNameNode) =>
            val typeNames = vsa
              .ptsOf(call, obj)
              .collectAll[SymbolicObject]
              .map(_.getTypeName)
              .filterNot(ValueSetResult.isDotPattern)
              .toSet

            val methodNames = vsa
              .ptsOf(call, methodNameNode, partialEval = true)
              .collect { case s: StringLiteral => s.value }
              .filterNot(ValueSetResult.isDotPattern)

            val resolvedCallees = if (typeNames.nonEmpty && methodNames.nonEmpty) {
              logger.info(
                s"[Extract Matching] receiver types: ${typeNames.mkString(", ")}, method names: ${methodNames.mkString(", ")}"
              )
              val exactMatching = findMethod(typeNames, methodNames).toList
              if (exactMatching.nonEmpty) {
                calleeFilter(hasReceiver = true, call.argument.size, false, Set(ModifierTypes.PUBLIC), exactMatching)
              } else {
                // [Extract Matching (Artemis)]
                logger.info(s"[Extract Matching (Artemis)] try to connect to __call method")
                val magicMethods = findMethod(typeNames, Set("__call")).toList
                connectMagicMethods(builder, call, magicMethods)
                // magic methods don't need parameter/argument size filtering
                magicMethods
              }
            } else {
              logger.info("[Heuristic Matching] VSA fails to infer method names or receiver types")
              val initialCandidates = if (typeNames.nonEmpty) {
                val typeDecls = typeNames.flatMap(getSubTypeDecls)
                typeDecls.method.toList
              } else if (methodNames.nonEmpty) {
                findMethod(methodNames).toList
              } else {
                // typeName and methodName are both unknown (.* pattern)
                cpg.method.toList
              }
              val arguments = call.argument.toList.tail.map(_.code)
              heuristicCalleeFilter(
                call,
                calleeFilter(
                  hasReceiver = true,
                  call.argument.size,
                  false,
                  Set(ModifierTypes.PUBLIC),
                  initialCandidates
                ),
                Some(arguments)
              )
            }
            connectCallees(builder, call, resolvedCallees)
            resolvedCallees
          case _ => List.empty
        }
      case _ => List.empty
    }
  }

  private def forVariableNew(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    def typeNameProcessor(typeName: String): String = {
      // over-approximation: file paths are not considered
      val elements = typeName.split("""[\\/]""")
      elements.last
    }

    logger.info(s"Resolve variable new ${call.log}")
    call.argumentOption(0) match {
      case Some(arg1) =>
        val typeNames = vsa.ptsOf(call, arg1, partialEval = true).collect { case x: StringLiteral => x.value }
        if (typeNames.nonEmpty) {
          val typeNamePattern = typeNames.map(typeNameProcessor).mkString("|")
          val objs            = vsa.ptsOf(call, call).collect { case x: SymbolicObject => x }
          objs.foreach(_.setTypeName(typeNamePattern))
          builder.setNodeProperty(call, Call.PropertyNames.TypeFullName, typeNamePattern)
        }
      case None =>
    }

    List.empty
  }

  /** @return
    *   (isEmptyReceiver, resolvedCallees)
    */
  private def forMethodCall(call: Call, builder: DiffGraphBuilder): (Boolean, Iterable[Method]) = {
    def isThisReceiver(call: Call): Boolean = call.receiver.forall(_.code == "$this")

    def handleNonEmptyReceiverCall(call: Call, objs: Iterable[SymbolicObject]): Iterable[Method] = {
      val resolvedCallees = {
        val typeName   = getObjectType(objs)
        val rawCallees = findMethod(typeName, call.name).toList
        val modifiers =
          if (isThisReceiver(call)) Set(ModifierTypes.PUBLIC, ModifierTypes.PRIVATE, ModifierTypes.PROTECTED)
          else Set(ModifierTypes.PUBLIC)
        val callees = calleeFilter(true, call.args.size, false, modifiers, rawCallees)
        if (callees.nonEmpty) callees
        else {
          logger.info(s"[Extract Matching (Artemis)] try to connect to __call method")
          val magicMethods = findMethod(typeName, "__call").toList
          connectMagicMethods(builder, call, magicMethods)
          magicMethods
        }
      }
      connectCallees(builder, call, resolvedCallees)
      resolvedCallees
    }

    def handleThisMethodCall(call: Call): Iterable[Method] = {
      call.method.typeDecl match {
        case Some(typeDecl) =>
          val callees = mutable.ListBuffer.empty[Method]
          // at this point, we cannot determine the type of $this. it may be an instance of any subclass of the current class.
          breakable {
            getSubTypeDecls(typeDecl).foreach(subTypeDecl =>
              val typeName   = subTypeDecl.name
              val rawCallees = calleeFilter(true, call.args.size, false, findMethod(typeName, call.name).toList)
              val (privateCallees, otherCallees) =
                rawCallees.partition(_.modifier.modifierTypeExact(ModifierTypes.PRIVATE).nonEmpty)
              callees ++= privateCallees
              callees ++= otherCallees
              if (privateCallees.nonEmpty)
                break
            )
          }
          connectCallees(builder, call, callees)
          if (callees.nonEmpty)
            unstableCalls += call
          callees
        case None => List.empty
      }
    }

    logger.info(s"Resolve method call ${call.log}")
    val objs = call.receiver
      .flatMap(rec => vsa.ptsOf(call, rec))
      .collectAll[SymbolicObject]
      .toList

    if (objs.nonEmpty) (false, handleNonEmptyReceiverCall(call, objs))
    else {
      if (isThisReceiver(call) && enhanced) (false, handleThisMethodCall(call))
      else {
        // caller collects calls where receiver types cannot be determined through VSA
        (true, List.empty)
      }
    }
  }

  private def forFunctionCall(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Resolve function call ${call.log}")
    val callees = findFunction(call.name).toList
    connectCallees(builder, call, callees)
    callees
  }

  /** Handle method calls where receiver types cannot be determined through VSA
    *
    * @param calleeThreshold
    *   if multiple (> calleeThreshold) classes contain the method names in this cluster, we skip this callsite
    */
  private def forEmptyReceiverCall(
    emptyReceiverCalls: mutable.ListBuffer[Call],
    calleeThreshold: Int,
    builder: DiffGraphBuilder
  ): Iterable[Method] = {
    val receiverCallsMap = mutable.Map.empty[String, mutable.Queue[Call]]

    def clusterReceiver(call: Call): Unit = {
      val visited = mutable.Set.empty[StoredNode]

      /** Backtrack data flow to the first encountered call */
      def trace2Call(node: StoredNode): Option[Call] = {
        node match {
          case c: Call => Some(c)
          case _ =>
            if (!visited.contains(node)) {
              visited.add(node)
              node._reachingDefIn.map(trace2Call).collectFirst { case Some(c) => c }
            } else
              None
        }
      }

      val callReceiver = call.receiver.map(trace2Call).buffered
      if (callReceiver.hasNext && callReceiver.head.isEmpty && call.receiver.nonEmpty) {
        // Unable to backtrack to call, directly use the original call.receiver for clustering
        receiverCallsMap.getOrElseUpdate(call.receiver.head.code, mutable.Queue.empty[Call]) += call
      } else {
        // Use the backtracked call as receiver for clustering,
        // e.g., bee.zipper.core.php.mvc.CodeIgniterDynamic and bee.zipper.core.php.mvc.ThinkPhpDynamic
        callReceiver.foreach {
          case Some(receiver) =>
            receiverCallsMap.getOrElseUpdate(receiver.code, mutable.Queue.empty[Call]) += call
          case None =>
        }
      }
    }

    def inferType(): Iterable[Method] = {
      receiverCallsMap.flatMap { case (receiver, calls) =>
        // Use function calls with the same receiver as constraints to infer its type
        val typeDecls = typeDeclFilter(cpg.typeDecl.toList, calls.toList)
        logger.info(s"infer result for receiver $receiver: ${typeDecls.map(_.name).mkString(", ")}")
        if (typeDecls.nonEmpty)
          calls.flatMap { call =>
            val rawCallees = typeDecls.flatMap(t => t.method.filter(m => m.name.toLowerCase == call.name.toLowerCase))
            val callees = calleeFilter(
              hasReceiver = true,
              call.args.size,
              isPartialMatchSize = false,
              Set(ModifierTypes.PUBLIC),
              rawCallees
            )
            if (callees.size > calleeThreshold) List.empty
            else {
              connectCallees(builder, call, callees)
              callees
            }
          }
        else {
          // Type inference failed, reverting to the old direct lookup method.
          calls.flatMap { call =>
            val initCallees = {
              val funName = call.name
              findMethod(funName).toList
            }
            val rawCallees =
              calleeFilter(
                hasReceiver = true,
                call.args.size,
                isPartialMatchSize = false,
                Set(ModifierTypes.PUBLIC),
                initCallees
              ).take(3)
            connectCallees(builder, call, rawCallees)
            rawCallees
          }
        }
      }
    }

    emptyReceiverCalls.foreach(clusterReceiver)
    inferType()
  }

  /** handle call_user_func and call_user_func_array
    */
  private def forCallUserFuncFamily(call: Call, passByArray: Boolean, builder: DiffGraphBuilder): Iterable[Method] = {

    /** create an alias for [[arg]] and connect dataflow edge from arg to alias
      */
    def connectAliasArgument(call: CfgNode, arg: CfgNode, argumentIndex: Int): NewIdentifier = {
      val tmpName = s"alias-${arg.id()}"
      val tmp =
        NewIdentifier()
          .name(tmpName)
          .lineNumber(call.lineNumber)
          .code(tmpName)
          .argumentIndex(argumentIndex)
      builder.addEdge(arg, tmp, EdgeTypes.REACHING_DEF)
      builder.addEdge(call, tmp, EdgeTypes.ARGUMENT)
      if (argumentIndex == 0)
        builder.addEdge(call, tmp, EdgeTypes.RECEIVER)
      builder.addEdge(call, tmp, EdgeTypes.AST)
      builder.addEdge(call.method, tmp, EdgeTypes.CONTAINS)
      tmp
    }

    logger.info(s"Resolve call_user_func_xxx ${call.log}")
    call.argumentOption(1) match {
      case None           => List.empty
      case Some(callable) =>
        // currently, we only consider single case because of the design of CPG
        val opt = vsa
          .ptsOf(call, callable, partialEval = true)
          .map(value => value -> resolveCallable(call, callable, value, enhanced, argumentsOptional = None))
          .find(_._2._1.nonEmpty)

        opt match {
          case None                            => List.empty
          case Some(value, (rawCallees, kind)) =>
            // backup the original arguments of call
            val allArgs = call.args
            // without callable
            val remainingArgs = call.args.tail

            val receivers: Set[CfgNode] = kind match {
              case CallableKind.Object =>
                Set(call.argument(1))
              case CallableKind.Array =>
                // val arr = value.as[SymbolicArray]
                // defUse.getAssignedValueOf(call, JArrayIndexPtr(arr, "0"))
                Set(call.argument(1))
              case _ =>
                Set.empty
            }

            def connectCallees(call: Call, callees: Iterable[Method]): Unit = {
              if (callees.nonEmpty) {
                call.outE(EdgeTypes.ARGUMENT).foreach(e => builder.removeEdge(e))
                call.outE(EdgeTypes.CALL).foreach(e => builder.removeEdge(e))
                callees.foreach(callee => builder.addEdge(call, callee, EdgeTypes.CALL))
              }
            }

            // call_user_func(callable $callback, mixed ...$args)
            def handleCallUserFunc(): Iterable[Method] = {
              val callees = kind match {
                case CallableKind.Object | CallableKind.Array =>
                  calleeFilter(
                    hasReceiver = true,
                    allArgs.size,
                    isPartialMatchSize = false,
                    Set(ModifierTypes.PUBLIC),
                    rawCallees
                  )
                case CallableKind.String =>
                  calleeFilter(
                    hasReceiver = false,
                    remainingArgs.size,
                    isPartialMatchSize = false,
                    Set(ModifierTypes.PUBLIC),
                    rawCallees
                  )
                case _ => rawCallees
              }

              connectCallees(call, callees)

              remainingArgs.zipWithIndex.foreach { case (arg, index) =>
                builder.addEdge(call, arg, EdgeTypes.ARGUMENT)
                builder.setNodeProperty(arg, PropertyNames.ARGUMENT_INDEX, index + 1)
              }

              callees
            }

            // call_user_func_array(callable $callback, array $args)
            def handleCallUserFuncArray(): Iterable[Method] = {
              // eval the symbolic value of the `args` argument
              val argArrayOption = call
                .argumentOption(2)
                .flatMap(x => vsa.ptsOf(call, x).collectFirst { case a: SymbolicArray => a })

              // argument size without receiver
              val argSize = argArrayOption match {
                case Some(argArray) => argArray.getConcrete.keys.size
                case None           => 1
              }

              val callees = kind match {
                case CallableKind.Object | CallableKind.Array =>
                  calleeFilter(
                    hasReceiver = true,
                    argSize + 1,
                    isPartialMatchSize = true,
                    Set(ModifierTypes.PUBLIC),
                    rawCallees
                  )
                case CallableKind.String =>
                  calleeFilter(
                    hasReceiver = false,
                    argSize,
                    isPartialMatchSize = true,
                    Set(ModifierTypes.PUBLIC),
                    rawCallees
                  )
                case _ => rawCallees
              }

              if (callees.isEmpty) return List.empty

              connectCallees(call, callees)

              val arr           = remainingArgs.head
              val newIdentifier = connectAliasArgument(call, arr, 1)
              InputStructureTag.bindTag(builder, newIdentifier, InputStructureTag.Value.ToHttpArrayValue)

              callees
            }

            val resolvedCallees =
              if (passByArray)
                handleCallUserFuncArray()
              else
                handleCallUserFunc()

            receivers.foreach(receiver =>
              // connect receiver edges for method call
              call.outE(EdgeTypes.RECEIVER).foreach(e => builder.removeEdge(e))
              connectAliasArgument(call, receiver, 0)
            )

            resolvedCallees
        } // opt match {
    }     // call.argumentOption(1) match {
  }
}
