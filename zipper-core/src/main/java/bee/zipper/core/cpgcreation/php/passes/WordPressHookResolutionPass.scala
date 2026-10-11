package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.term.{StringLiteral, SymbolicValue}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.WordPressHook
import bee.zipper.core.cpgcreation.x.RegexEscaper
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import org.slf4j.LoggerFactory

import scala.collection.mutable

object WordPressHookResolutionLayer {
  def run(cpg: Cpg, vsa: ValueSetResult, enhanced: Boolean = true, iterations: Option[Int] = Some(1)): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new WordPressHookResolutionLayer(vsa, enhanced, iterations)
    layer.run(context)
  }
}

private class WordPressHookResolutionLayer(vsa: ValueSetResult, enhanced: Boolean, iterations: Option[Int])
    extends LayerCreator {
  override val overlayName: String = "WordPressHookResolutionPass"

  override val description: String = "Resolve WordPress hook calls (add_filter/add_action and apply_filters/do_action)"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new WordPressHookResolutionPass(cpg, vsa, enhanced, iterations)
    pass.createAndApply()
  }
}

private enum HookCallKind {
  case AddFilter, AddAction, ApplyFilters, DoAction, NonHookCall
}

private object HookCallKind {
  def getKind(call: Call): HookCallKind = call match {
    case _ if isAddFilter(call)    => AddFilter
    case _ if isAddAction(call)    => AddAction
    case _ if isApplyFilters(call) => ApplyFilters
    case _ if isDoAction(call)     => DoAction
    case _                         => NonHookCall
  }

  def isAddFilter(call: Call): Boolean = {
    call.name == "add_filter"
  }

  def isAddAction(call: Call): Boolean = {
    call.name == "add_action"
  }

  def isApplyFilters(call: Call): Boolean = {
    call.name == "apply_filters"
  }

  def isDoAction(call: Call): Boolean = {
    call.name == "do_action"
  }
}

/** WordPress Hook Registration info
  *
  * @param hookName
  *   the hook name
  * @param callback
  *   the callback method
  * @param priority
  *   the priority (optional)
  */
private case class HookRegistration(hookName: String, callback: Method, priority: Option[Int] = None)

class WordPressHookResolutionPass(val cpg: Cpg, val vsa: ValueSetResult, enhanced: Boolean, iterations: Option[Int])
    extends CpgPass(cpg),
      PhpCallLinkerPassBase {

  private val logger = LoggerFactory.getLogger(this.getClass)

  /** Registry of hook name to callback methods */
  private val hookRegistry = mutable.Map.empty[String, mutable.ListBuffer[Method]]

  /** Calls that have been resolved but can be more precise in future iteration */
  private val unstableCalls = mutable.Set.empty[Call]

  override def run(builder: DiffGraphBuilder): Unit = solve()

  /** Resolve WordPress hooks iteratively */
  private def solve(): Unit = {
    val worklist       = initWorkList()
    var iterationCount = 0

    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      logger.info(s"The ${iterationCount + 1}th iteration for resolving WordPress hooks")
      val builder         = Cpg.newDiffGraphBuilder
      val resolvedCallees = mutable.Set.empty[Method]
      val size            = worklist.size

      for (i <- 0 until size) {
        val (call, kind) = worklist.dequeue()
        val callees = kind match {
          case HookCallKind.NonHookCall  => List.empty
          case HookCallKind.AddFilter    => forAddFilter(call, builder)
          case HookCallKind.AddAction    => forAddAction(call, builder)
          case HookCallKind.ApplyFilters => forApplyFilters(call, builder)
          case HookCallKind.DoAction     => forDoAction(call, builder)
        }
        resolvedCallees ++= callees
      }

      logger.info(s"${resolvedCallees.size} new callees are resolved")

      // Apply the changes to CPG
      applyCpgDiff(builder)

      // Add unresolved calls in new callees to worklist
      val unresolvedCalls =
        resolvedCallees
          .flatMap(getUnresolvedCalls)
          .map(call => (call, HookCallKind.getKind(call)))
      worklist ++= unresolvedCalls

      // Clean the VSA cache
      vsa.clear()
      iterationCount += 1
    }
  }

  private def initWorkList(): mutable.Queue[(Call, HookCallKind)] = {
    val worklist = mutable.Queue.empty[(Call, HookCallKind)]
    val kindToCalls =
      cpg.call
        .map(call => (call, HookCallKind.getKind(call)))
        .groupBy(_._2)
        .withDefaultValue(List.empty)

    import HookCallKind.*

    // First pass: collect registrations (add_filter/add_action)
    val registrationOrder = List(AddFilter, AddAction)
    registrationOrder.foreach { kind =>
      worklist ++= kindToCalls(kind)
    }

    // Second pass: resolve trigger points (apply_filters/do_action)
    val triggerOrder = List(ApplyFilters, DoAction)
    triggerOrder.foreach { kind =>
      worklist ++= kindToCalls(kind)
    }

    worklist
  }

  private def getUnresolvedCalls(method: Method): List[Call] = {
    def isUnresolvedCall(c: Call): Boolean = {
      val callees = NoResolve.getCalledMethods(c)
      callees.isEmpty || callees.exists(_.isExternal) || unstableCalls.contains(c)
    }

    method.cfgNode.isCall
      .filter(c => HookCallKind.getKind(c) != HookCallKind.NonHookCall)
      .filter(isUnresolvedCall)
      .toList
  }

  /** Process add_filter calls to collect hook registrations */
  private def forAddFilter(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Collect add_filter registration ${call.log}")
    collectHookRegistration(call, builder)
  }

  /** Process add_action calls to collect hook registrations */
  private def forAddAction(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Collect add_action registration ${call.log}")
    collectHookRegistration(call, builder)
  }

  /** Collect hook registration from add_filter/add_action calls
    *
    * @param call
    *   the add_filter or add_action call
    * @param builder
    *   the diff graph builder
    * @return
    *   empty list (registration doesn't resolve new callees directly)
    */
  private def collectHookRegistration(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    // add_filter($tag, $function_to_add, $priority, $accepted_args)
    // add_action($tag, $function_to_add, $priority, $accepted_args)

    val hookNameOpt = call.argumentOption(1)
    val callbackOpt = call.argumentOption(2)

    (hookNameOpt, callbackOpt) match {
      case (Some(hookNameNode), Some(callbackNode)) =>
        // Get hook names via VSA
        val hookNames = vsa
          .ptsOf(call, hookNameNode, partialEval = true)
          .collect { case s: StringLiteral => s.value }
          .toSet

        // Resolve callbacks
        val callbacks = resolveHookCallback(call, callbackNode)

        // Register each combination
        for {
          hookName <- hookNames
          callback <- callbacks
        } {
          hookRegistry
            .getOrElseUpdate(hookName, mutable.ListBuffer.empty)
            .addOne(callback)
          logger.debug(s"Registered callback ${callback.fullName} for hook '$hookName'")
        }

        // Add feature tag
        FeatureTagger.bind(builder, call, WordPressHook)

      case _ =>
        logger.warn(s"Invalid add_filter/add_action call structure: ${call.log}")
    }

    List.empty // Registration doesn't directly resolve callees
  }

  /** Resolve callback parameter to actual methods */
  private def resolveHookCallback(call: Call, callbackNode: CfgNode): List[Method] = {
    val pts = vsa.ptsOf(call, callbackNode, partialEval = true)

    pts.flatMap { callableValue =>
      val (rawCallees, _) = resolveCallable(call, callbackNode, callableValue, enhanced, argumentsOptional = None)
      rawCallees
    }.toList
  }

  /** Process apply_filters calls to resolve hook triggers */
  private def forApplyFilters(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Resolve apply_filters ${call.log}")
    resolveHookTrigger(call, builder, isFilter = true)
  }

  /** Process do_action calls to resolve hook triggers */
  private def forDoAction(call: Call, builder: DiffGraphBuilder): Iterable[Method] = {
    logger.info(s"Resolve do_action ${call.log}")
    resolveHookTrigger(call, builder, isFilter = false)
  }

  /** Resolve hook trigger points (apply_filters/do_action) */
  private def resolveHookTrigger(call: Call, builder: DiffGraphBuilder, isFilter: Boolean): Iterable[Method] = {
    // apply_filters($tag, $value, ...$additional_args)
    // do_action($tag, ...$args)

    call.argumentOption(1) match {
      case Some(hookNameNode) =>
        // Get possible hook names
        val hookNames = vsa
          .ptsOf(call, hookNameNode, partialEval = true)
          .collect { case s: StringLiteral => s.value }
          .toSet

        // Find registered callbacks
        val allCallees = mutable.ListBuffer.empty[Method]

        for (hookName <- hookNames) {
          val directCallees = hookRegistry.getOrElse(hookName, mutable.ListBuffer.empty).toList
          allCallees ++= directCallees

          // If enhanced mode and no direct matches, try fuzzy matching
          if (enhanced && directCallees.isEmpty && !ValueSetResult.isDotPattern(hookName)) {
            val fuzzyCallees = findFuzzyHookMatches(hookName)
            allCallees ++= fuzzyCallees
          }
        }

        // Connect call edges and restructure arguments
        if (allCallees.nonEmpty) {
          // Keep a snapshot of original arguments (needed after we remove edges)
          val originalArgs = call.argument.l.sortBy(_.argumentIndex)

          // 1. Remove original CALL and ARGUMENT edges
          call.outE(EdgeTypes.CALL).foreach(builder.removeEdge)
          call.outE(EdgeTypes.ARGUMENT).foreach(builder.removeEdge)

          // 2. Connect new CALL edges to all potential callbacks
          connectCallees(builder, call, allCallees.toList)

          // 3. Re-link arguments for the callbacks (skip the first argument which is the hook name)
          val callbackArgs = originalArgs.drop(1)
          callbackArgs.zipWithIndex.foreach { case (arg, index) =>
            val calleeArgIndex = index + 1
            builder.addEdge(call, arg, EdgeTypes.ARGUMENT)
            builder.setNodeProperty(arg, PropertyNames.ARGUMENT_INDEX, calleeArgIndex)
          }

          // 4. For apply_filters, handle the return value data flow
          if (isFilter) {
            // The return can be the original value (arg 2) or from any callback.
            call.argumentOption(2).foreach { valueNode =>
              builder.addEdge(valueNode, call, EdgeTypes.REACHING_DEF)
            }
            allCallees.foreach { callback =>
              callback.methodReturn.foreach { ret =>
                builder.addEdge(ret, call, EdgeTypes.REACHING_DEF)
              }
            }
          }

          // 5. Add feature tag and handle unstable calls
          FeatureTagger.bind(builder, call, WordPressHook)
          if (allCallees.size > 1) {
            unstableCalls += call
          }
        }

        allCallees.toList

      case None =>
        logger.warn(s"Invalid apply_filters/do_action call structure: ${call.log}")
        List.empty
    }
  }

  /** Find fuzzy matches for hook names with .* patterns */
  private def findFuzzyHookMatches(hookNamePattern: String): List[Method] = {
    if (!enhanced || ValueSetResult.isDotPattern(hookNamePattern)) {
      return List.empty
    }

    try {
      val regex          = ("^.*" + RegexEscaper.escape(hookNamePattern) + "$").r
      val matchedCallees = mutable.ListBuffer.empty[Method]

      hookRegistry.foreach { case (registeredHook, callbacks) =>
        if (regex.matches(registeredHook)) {
          matchedCallees ++= callbacks
        }
      }

      matchedCallees.toList
    } catch {
      case e: Exception =>
        logger.warn(s"Fuzzy hook pattern <$hookNamePattern> syntax exception")
        List.empty
    }
  }
}
