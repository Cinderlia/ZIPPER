package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.extend.{SymbolicArray, SymbolicObject}
import bee.zipper.api.solver.sym.term.{StringLiteral, SymbolicValue}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.x.{CallLinkerPassBase, RegexEscaper}
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.TokenSimilarity
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{ModifierTypes, Operators}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable
import scala.util.control.Breaks.{break, breakable}

enum CallableKind {
  case NonCallable, String, Object, Array
}

trait PhpCallLinkerPassBase extends CallLinkerPassBase {

  /** resolve the callees of the callable object in PHP
    *
    * @param argumentsOptional
    *   None if the arguments are passed as an array (e.g., call_user_func_array). Note it doesn't contain the receiver
    */
  protected final def resolveCallable(
    ctx: Call,
    exp: CfgNode,
    callable: SymbolicValue,
    enhanced: Boolean,
    argumentsOptional: Option[List[String]] = None
  ): (List[Method], CallableKind) = {
    callable match {
      case StringLiteral(namePattern) =>
        if (ValueSetResult.isDotPattern(namePattern) && enhanced) {
          val rule = deriveAllowDenyRule(ctx.method, ctx, exp.code)
          logger.info(s"Rule for ${exp.code}: $rule")
          val methods = if (rule.allowed.nonEmpty) {
            val namePattern = RegexEscaper.escape(rule.allowed.mkString("|"))
            cpg.method(namePattern).toList
          } else {
            logger.info("Try to use heuristic filter")
            val container = ctx.method
            // the scope is limited to functions within the file of the call site
            val candidates = container.file.method
              .filter(m => m != container && m.name != "<global>")
              .filter(m => rule.isAccept(m.name))
              .toList
            heuristicCalleeFilter(ctx, candidates, argumentsOptional)
          }
          (methods, CallableKind.String)
        } else {
          val methods =
            try {
              cpg.method(RegexEscaper.escape(namePattern)).toList
            } catch {
              case e: Exception =>
                logger.warn(s"pattern <$namePattern> syntax exception")
                List.empty
            }
          (methods, CallableKind.String)
        }
      case obj: SymbolicObject =>
        val methods = findMethod(obj.getTypeName, "__invoke").toList
        (methods, CallableKind.Object)
      case array: SymbolicArray if enhanced =>
        array.get("1").collect { case x: StringLiteral => x.value } match {
          case Some(namePattern) =>
            array.get("0") match {
              // Case 1: Instance method call -> array($obj, 'method')
              case Some(obj: SymbolicObject) =>
                val candidates = findMethod(obj.getTypeName, namePattern).toList
                val methods = candidates.filter(m =>
                  m.parameter.exists(_.index == 0) &&
                    m.modifier.modifierTypeExact(ModifierTypes.STATIC).isEmpty
                )
                (methods, CallableKind.Array)
              // Case 2: Static method call -> array('ClassName', 'method')
              case Some(StringLiteral(typeName)) =>
                val candidates = findMethod(typeName, namePattern).toList
                val methods =
                  candidates.filter(m => m.modifier.modifierTypeExact(ModifierTypes.STATIC).nonEmpty)
                (methods, CallableKind.Array)
              case _ =>
                (List.empty, CallableKind.NonCallable)
            }
          case None =>
            (List.empty, CallableKind.NonCallable)
        }
      case _ => (List.empty, CallableKind.NonCallable)
    }
  }

  /** Filter callees by heuristic rules (including parameter and calling context similarity)
    *
    * @param argumentsOptional
    *   None if the arguments are passed as an array (e.g., call_user_func_array). Note it doesn't contain the receiver
    *   argument because we only compare the similarity between explicit arguments and parameters
    * @param topN
    *   * The maximum number of candidates to return after ranking.
    */
  protected final def heuristicCalleeFilter(
    ctx: Call,
    candidates: List[Method],
    argumentsOptional: Option[List[String]] = None,
    threshold: Double = 0.7,
    topN: Int = 6
  ): List[Method] = {
    argumentsOptional match {
      case Some(arguments) if arguments.isEmpty =>
        // if there is no argument, we don't connect any callee
        List.empty
      case Some(arguments) =>
        logger.info(s"Try to use argument-parameter similarity, arguments: ${arguments.mkString(", ")}")

        def extractParameters(callee: Method): List[String] = {
          callee.parameter
            .filter(p => p.index >= 1) // ignore the receiver
            .sortBy(_.index)
            .map(_.name)
            .toList
        }

        // calculate the maximum similarity score for each candidate
        val scoredCandidates = candidates.map { callee =>
          val params = extractParameters(callee)
          val maxSimilarity = arguments
            .zip(params)
            .map { case (arg, param) =>
              val argTokens   = TokenSimilarity.tokenizeIdentifier(arg)
              val paramTokens = TokenSimilarity.tokenizeIdentifier(param)
              TokenSimilarity.calculate(argTokens, paramTokens)
            }
            .maxOption
            .getOrElse(0.0)
          (callee, maxSimilarity)
        }

        val result = scoredCandidates
          .filter { case (_, similarity) => similarity >= threshold } // filter out those below the threshold
          .sortBy { case (_, similarity) => -similarity } // sort in descending order by similarity
          .take(topN)
          .map { case (callee, similarity) =>
            logger.info(f"Matched callee ${callee.name} with argument similarity: $similarity%.2f")
            callee
          }

        result
      case None =>
        logger.info("Try to use calling context similarity")

        // filter by calling context similarity
        def extractMethodCtx(method: Method): Set[String] = {
          val ids = method.cfgNode.isIdentifier.map(_.name).toList :+ method.name
          ids
            .flatMap(id => TokenSimilarity.tokenizeIdentifier(id))
            .filter(x => x.length > 3 && !HeuristicStopWords.list.contains(x))
            .toSet
        }

        val callsiteCtxTokens = extractMethodCtx(ctx.method)
        logger.info(s"Callsite context tokens: ${callsiteCtxTokens.mkString(", ")}")

        val scoredCandidates = candidates.map { callee =>
          val calleeCtxTokens = extractMethodCtx(callee)
          val intersection    = callsiteCtxTokens.intersect(calleeCtxTokens)
          (callee, intersection)
        }

        val result = scoredCandidates
          .filter { case (_, intersection) => intersection.nonEmpty }
          .sortBy { case (_, intersection) => -intersection.size }
          .take(topN)
          .map { case (callee, intersection) =>
            logger.info(s"Matched callee ${callee.name} with context tokens: ${intersection.mkString(", ")}")
            callee
          }

        result
    }
  }

  private object HeuristicStopWords {
    val list: Set[String] = Set(
      "a",
      "an",
      "the",
      "in",
      "on",
      "at",
      "of",
      "to",
      "for",
      "with",
      "by",
      "from",
      "and",
      "or",
      "but",
      "so",
      "if",
      "then",
      "else",
      "when",
      "as",
      "is",
      "are",
      "was",
      "were",
      "be",
      "been",
      "being",
      "has",
      "have",
      "had",
      "do",
      "does",
      "did",
      "foo",
      "bar",
      "baz",
      "tmp",
      "temp",
      "tmp",
      "val",
      "var",
      "let",
      "const",
      "obj",
      "object",
      "arr",
      "array",
      "list",
      "map",
      "set",
      "dict",
      "str",
      "string",
      "int",
      "integer",
      "num",
      "number",
      "bool",
      "boolean",
      "float",
      "double",
      "item",
      "items",
      "element",
      "elements",
      "value",
      "values",
      "key",
      "keys",
      "param",
      "params",
      "parameter",
      "parameters",
      "arg",
      "args",
      "argument",
      "arguments",
      "result",
      "results",
      "ret",
      "return",
      "res",
      "get",
      "set",
      "add",
      "new",
      "create",
      "init",
      "build",
      "make",
      "is",
      "has",
      "id",
      "old",
      "default",
      "current",
      "my",
      "this",
      "self",
      "super",
      "index",
      "idx",
      "i",
      "j",
      "k"
    )
  }

  /** Represents a rule that specifies which items are allowed and which are denied. It can be viewed as a simplified
    * representation of an automaton or a set
    */
  protected case class AllowDenyRule(allowed: Set[String], denied: Set[String]) {
    def isEmpty: Boolean = allowed.isEmpty && denied.isEmpty

    /** Checking if the rule (automaton) accepts the given string.
      */
    def isAccept(string: String): Boolean = {
      (allowed.isEmpty || allowed.contains(string)) && (denied.isEmpty || !denied.contains(string))
    }

    override def toString: String =
      s"Rule(allowed={${allowed.mkString(", ")}}, denied={${denied.mkString(", ")}})"
  }

  protected object AllowDenyRule {
    val empty: AllowDenyRule = AllowDenyRule(Set.empty, Set.empty)

    /** Semantic-preserving union operation
      */
    def union(rules: List[AllowDenyRule]): AllowDenyRule = {
      rules
        .reduceOption { (acc, rule) =>
          // 'allowed' becomes more permissive: an item is allowed if any rule allows it.
          val combinedAllowed = acc.allowed.union(rule.allowed)
          // 'denied' also becomes more permissive: an item is only denied if all rules deny it.
          val combinedDenied = acc.denied.intersect(rule.denied)
          AllowDenyRule(combinedAllowed, combinedDenied)
        }
        .getOrElse(empty)
    }

    /** Semantic-preserving intersect operation
      */
    def intersect(rules: List[AllowDenyRule]): AllowDenyRule = {
      rules
        .reduceOption { (acc, rule) =>
          // 'allowed' becomes more restrictive: an item must be allowed by all rules.
          val commonAllowed = acc.allowed.intersect(rule.allowed)
          // 'denied' also becomes more restrictive: a denial from any rule is enough to deny.
          val commonDenied = acc.denied.union(rule.denied)
          AllowDenyRule(commonAllowed, commonDenied)
        }
        .getOrElse(empty)
    }

    def sum(os: List[AllowDenyRule]): AllowDenyRule = {
      os.foldLeft(empty) { (acc, c) =>
        AllowDenyRule(acc.allowed ++ c.allowed, acc.denied ++ c.denied)
      }
    }

    def allow(value: String): AllowDenyRule = AllowDenyRule(Set(value), Set.empty)

    def allow(values: Set[String]): AllowDenyRule = AllowDenyRule(values, Set.empty)

    def deny(value: String): AllowDenyRule = AllowDenyRule(Set.empty, Set(value))

    def deny(values: Set[String]): AllowDenyRule = AllowDenyRule(Set.empty, values)

    /** Creates a rule conditionally based on a boolean flag
      */
    def apply(values: Set[String], isAllowed: Boolean): AllowDenyRule = if (isAllowed) allow(values) else deny(values)

    def apply(value: String, isAllowed: Boolean): AllowDenyRule = apply(Set(value), isAllowed)
  }

  /** Derive AllowDenyRule on varName from control dependency graph
    */
  protected def deriveAllowDenyRule(method: Method, ctx: Call, varName: String): AllowDenyRule = {

    /** Find a set containing the variable name we are tracking.
      */
    def findSimilarIdentifiers(): Set[String] = {
      Set(varName)
    }

    val trackedNames = findSimilarIdentifiers()

    /** Check if the cfg node is a tracked variable
      */
    def isTrackedVar(node: CfgNode): Boolean = trackedNames.exists(node.code.contains)

    /** Determine if the call performs a comparison on tracked variables
      */
    def isChecking(call: Call): Boolean = call.argument.size >= 2 && isTrackedVar(call.argument(1))

    /** Evaluates a condition expression recursively to derive an AllowDenyRule.
      */
    def evalExp(exp: CfgNode, isConditionMet: Boolean): AllowDenyRule = {
      exp match {
        case call: Call =>
          val argSize = call.argument.size
          call.name match {
            case Operators.equals | PhpOperators.identicalOp if isChecking(call) =>
              evalExp(call.argument(2), isConditionMet)
            case Operators.notEquals if isChecking(call) =>
              evalExp(call.argument(2), !isConditionMet)
            case Operators.logicalOr | Operators.logicalAnd if isChecking(call) =>
              val left  = evalExp(call.argument(1), isConditionMet)
              val right = evalExp(call.argument(2), isConditionMet)
              AllowDenyRule.sum(List(left, right))
            case "in_array" if isChecking(call) =>
              val pts = vsa.ptsOf(call, call.argument(2)).collect { case s: StringLiteral => s.value }
              AllowDenyRule(pts, isConditionMet)
            case _ =>
              AllowDenyRule.empty
          }
        case lit: Literal if lit.isStr => AllowDenyRule(lit.getString, isConditionMet)
        case _                         => AllowDenyRule.empty
      }
    }

    def whichBranch(cs: ControlStructure, node: CfgNode): Option[Boolean] = {
      if (cs.whenTrue.ast.contains(node)) Some(true)
      else if (cs.whenFalse.ast.contains(node)) Some(false)
      else None
    }

    /** Traverses up the control flow graph from a starting node, collecting rules from each enclosing control structure
      */
    def traverseUp(): List[AllowDenyRule] = {
      val rules = mutable.ListBuffer.empty[AllowDenyRule]
      breakable {
        var node: CfgNode = ctx
        while (true) {
          val cso = node.getClosest[ControlStructure]
          if (cso.isEmpty)
            break
          val cs = cso.get
          cs.condition.headOption.foreach(condition =>
            whichBranch(cs, ctx).foreach(pass => rules += evalExp(condition, pass))
          )
          node = cs
        }
      }
      rules.toList
    }

    val rules = traverseUp()
    AllowDenyRule.intersect(rules)
  }
}
