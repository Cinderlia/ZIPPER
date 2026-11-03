package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** PHP `include`/`require` shares the variable scope of the including file: variables defined before the inclusion are
  * visible in the included file. The CPG instead represents each file as its own `<global>` method, so no dataflow
  * crosses the inclusion boundary.
  *
  * This pass models the shared scope by turning the free variables of the included file's `<global>` method into
  * parameters of that method and adding matching identifier arguments at the inclusion call site. The engine can then
  * map a parameter to the corresponding argument (`TaskCreator.tasksForParams`) and continue the analysis in the
  * including file.
  *
  * Because the pass may run after the reaching-def pass has been applied, the necessary `REACHING_DEF` edges for the
  * new argument/parameter nodes are added directly: caller-side definitions -> argument, and parameter -> uses inside
  * the included file.
  */
class PhpIncludeScopePass(cpg: Cpg) extends CpgPass(cpg) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  private val includeNames = Set("include", "include_once", "require", "require_once")

  /** Variables that are always available and must not be turned into parameters. */
  private val reserved = Set(
    "this",
    "GLOBALS",
    "argv",
    "argc",
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_SERVER",
    "_SESSION",
    "_ENV",
    "_FILES",
    "HTTP_GET_VARS",
    "HTTP_POST_VARS",
    "HTTP_COOKIE_VARS",
    "HTTP_SERVER_VARS",
    "HTTP_ENV_VARS",
    "HTTP_SESSION_VARS"
  )

  private val maxParams = 40
  private val maxRounds = 6

  private def isAssignment(call: Call): Boolean = call.name.startsWith("<operator>.assignment")

  private def isDefinedIdentifier(id: Identifier): Boolean =
    id.astParent match {
      case call: Call if isAssignment(call) => call.argumentOption(1).contains(id)
      case _                                => false
    }

  /** Variables that the top-level code of [[global]] reads but does not define. */
  private def freeVariables(global: Method): List[String] = {
    val ids     = global.ast.isIdentifier.l
    val defined = ids.filter(isDefinedIdentifier).map(_.name).toSet
    ids.map(_.name).distinct.filter(name => name.nonEmpty && !reserved.contains(name) && !defined.contains(name))
  }

  private val StringLiteral = """['"]([^'"\n]+\.(?:php|inc|phtml))['"]""".r

  private def literalPaths(code: String): List[String] =
    StringLiteral.findAllMatchIn(code).map(_.group(1)).toList

  private def findGlobalMethod(path: String): List[Method] = {
    val normalized = path.replace('\\', '/').stripPrefix("./").stripPrefix("/")
    val candidates = cpg.file.l.filter { file =>
      val name = file.name.replace('\\', '/')
      name == normalized || name.endsWith("/" + normalized)
    }
    if (candidates.size > 1)
      logger.warn(s"[include-scope] ambiguous include target $path: ${candidates.map(_.name).sorted.mkString(", ")}")
    candidates.sortBy(_.name.length).headOption.toList.flatMap(_.method.nameExact("<global>").l)
  }

  /** The `<global>` methods of the included files: those already linked by a CALL edge (file inclusion resolution) and
    * those that can be resolved from a literal path argument.
    */
  private def targetMethods(call: Call): List[Method] = {
    val viaEdge = call.out(EdgeTypes.CALL).collectAll[Method].filter(_.name == "<global>").l
    val viaPath = call.argumentOption(1).toList.flatMap(arg => literalPaths(arg.code)).flatMap(findGlobalMethod)
    (viaEdge ++ viaPath).distinctBy(_.id())
  }

  override def run(builder: DiffGraphBuilder): Unit = {
    val calls = cpg.call.filter(call => includeNames.contains(call.name)).l
    if (calls.isEmpty) {
      logger.info("[include-scope] no include/require calls found")
      return
    }

    val pairs = calls
      .flatMap(call => targetMethods(call).map(target => (call, target)))
      .distinctBy(pair => (pair._1.id(), pair._2.id()))

    logger.info(s"[include-scope] include calls=${calls.size} resolved targets=${pairs.size}")
    if (java.lang.Boolean.getBoolean("zipper.include.debug")) {
      pairs.foreach { case (call, target) =>
        logger.info(s"[include-scope] ${call.method.filename}:${call.lineNumber} -> ${target.filename}")
      }
    }

    // Nodes added by this pass are not visible to CPG traversals until the diff is applied, so track them locally.
    val addedParams = mutable.Map.empty[Long, mutable.Set[String]]
    val addedArgs   = mutable.Map.empty[Long, mutable.Set[String]]

    var added   = 0
    var round   = 1
    var changed = true
    while (changed && round <= maxRounds) {
      changed = false
      pairs.foreach { case (call, target) =>
        val caller = call.method
        if (caller != null) {
          val definedInTarget =
            target.parameter.name.toSet ++ addedParams.getOrElse(target.id(), mutable.Set.empty[String])
          val alreadyPassed =
            call.argument.l.map(_.code.stripPrefix("$")).toSet ++ addedArgs.getOrElse(
              call.id(),
              mutable.Set.empty[String]
            )
          val wanted = freeVariables(target)
            .filterNot(definedInTarget.contains)
            .filterNot(alreadyPassed.contains)
            .take(maxParams)

          wanted.foreach { name =>
            val index = target.parameter.size + 1
            val order = target.parameter.size + 1
            val param = NewMethodParameterIn()
            param.name = name
            param.code = "$" + name
            param.index = index
            param.order = order
            param.typeFullName = "ANY"
            param.evaluationStrategy = "BY_VALUE"
            param.lineNumber = call.lineNumber
            builder.addNode(param)
            builder.addEdge(target, param, EdgeTypes.AST)

            val arg = NewIdentifier()
            arg.name = name
            arg.code = "$" + name
            arg.argumentIndex = index
            arg.order = index
            arg.typeFullName = "ANY"
            arg.lineNumber = call.lineNumber
            builder.addNode(arg)
            builder.addEdge(call, arg, EdgeTypes.ARGUMENT)
            builder.addEdge(call, arg, EdgeTypes.AST)
            builder.addEdge(caller, arg, EdgeTypes.CONTAINS)

            // caller-side definitions of the variable reach the synthesized argument
            caller.ast.isCall.filter(isAssignment).foreach { assignment =>
              assignment.argumentOption(1).collect { case id: Identifier if id.name == name => id }.foreach { lhs =>
                builder.addEdge(lhs, arg, EdgeTypes.REACHING_DEF)
              }
            }

            // inside the included file the parameter defines the variable
            target.ast.isIdentifier.filter(_.name == name).foreach { use =>
              builder.addEdge(param, use, EdgeTypes.REACHING_DEF)
            }

            // keep the argument part of the CFG so that later passes can reason about it
            call.cfgPrev.l.foreach(previous => builder.addEdge(previous, arg, EdgeTypes.CFG))
            builder.addEdge(arg, call, EdgeTypes.CFG)

            if (!call.out(EdgeTypes.CALL).collectAll[Method].exists(_.id() == target.id()))
              builder.addEdge(call, target, EdgeTypes.CALL)

            if (!addedParams.contains(target.id())) addedParams(target.id()) = mutable.Set.empty[String]
            addedParams(target.id()) += name
            if (!addedArgs.contains(call.id())) addedArgs(call.id()) = mutable.Set.empty[String]
            addedArgs(call.id()) += name

            added += 1
            changed = true
          }
        }
      }
      logger.info(s"[include-scope] round $round added=$added")
      round += 1
    }

    logger.info(s"[include-scope] done: arguments=$added include-targets=${pairs.map(_._2.id()).distinct.size}")
  }
}
