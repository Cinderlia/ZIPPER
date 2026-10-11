package bee.zipper.core.analysis.vsa

import bee.zipper.api.solver.sym.SymCast
import bee.zipper.api.solver.sym.extend.*
import bee.zipper.api.solver.sym.term.*
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.bbcfg.*
import bee.zipper.core.analysis.model.cs.PathCallGraph
import bee.zipper.core.analysis.model.summary.{BlockSummary, FunSummary}
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import bee.zipper.util.CollectionExtension.*
import bee.zipper.util.MemoryCache
import bee.zipper.util.MemoryCache.getOrElseUpdate
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Literal, Method}
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable
import scala.reflect.ClassTag

class DefaultSummaryValueSetResult(cpg: Cpg)(implicit ctx: AnalysisContext) extends OnDemandValueSetResult {
  import ctx.translator.translate

  private val logger = LoggerFactory.getLogger(this.getClass)
  private val cache1 = MemoryCache.mk[(CfgNode, Boolean), Set[SymbolicValue]]
  private type CacheKey = (DefaultBasicBlock, String)
  private type Result   = (Set[SymbolicValue], List[SideEffectEnv])
  private val cache2        = MemoryCache.mk[(CacheKey, Boolean), Result]
  private val constantTable = buildConstantTable()

  /** The evaluation environment
    * @param m
    *   the method containing [[bb]]
    * @param bbCfg
    *   the basic block CFG of [[m]]
    * @param funSummary
    *   the function summary of [[m]]
    * @param partialEval
    *   determine whether to perform partial evaluation
    * @param isInInitMethod
    *   Flag whether it's currently in the init method, which is used to avoid infinite recursion.
    */
  private case class Env(
    m: Method,
    bbCfg: DefaultBBCfg,
    funSummary: FunSummary,
    bb: DefaultBasicBlock,
    partialEval: Boolean,
    isInInitMethod: Boolean,
    walk: Set[DefaultBasicBlock],
    pathCallGraph: Option[PathCallGraph]
  )

  /** @param name
    *   the name of the variable on which the side effect is applied
    * @param sideEffect
    *   the side effect
    * @param env
    *   the basic block environment that contains this side effect
    */
  private case class SideEffectEnv(name: String, sideEffect: SideEffect, env: Env)

  /** The evaluation environment of symbolic value
    * @param env
    *   the evaluation environment
    * @param symbol
    *   the symbolic value to be evaluated
    */
  private case class SymbolicValueEnv(env: Env, symbol: SymbolicValue)

  private def location(node: CfgNode, v: CfgNode): String = {
    def showCode(code: String, maxLen: Int = 25): String = {
      if (code.length <= maxLen) code
      else code.take(maxLen) + "..."
    }

    val exprCode   = showCode(v.code)
    val ctxCode    = showCode(node.code)
    val fileName   = node.file.name.headOption.getOrElse("")
    val lineNumber = node.lineNumber.getOrElse(0)
    s"`$exprCode` @ `$ctxCode:$fileName:$lineNumber`"
  }

  /** @param partialEval
    *   indicate it's in string partial evaluation mode
    */
  override def ptsOf(node: CfgNode, v: CfgNode, partialEval: Boolean = false)(implicit
    pathCallGraph: Option[PathCallGraph] = None
  ): Set[SymbolicValue] = {
    try {
      val pts = cache1.get(
        (v, partialEval),
        _ => {
          translate(v) match {
            case jv: Var =>
              val name           = jv.toString
              val m              = v.method
              val bbCfg          = DefaultBBCfg.create(m, unrolling = true)
              val isInInitMethod = isInitMethod(m)
              val env =
                Env(
                  m,
                  bbCfg,
                  FunSummary.create(m),
                  bbCfg.bbOf(node),
                  partialEval,
                  isInInitMethod,
                  Set.empty,
                  pathCallGraph
                )
              val (pts, sideEffects) = evalVariable(env, name)
              // transform `dummy object` to `.*` pattern if it's in partial evaluation mode
              if (partialEval && pts.size == 1 && pts.head.is[DummyObject])
                Set(ValueSetResult.dotPatternSym)
              else
                pts
            case x @ _ =>
              logger.warn(s"unimplemented for ${x.getClass.getName}")
              Set.empty
          }
        }
      )
      logger.info(s"ptsOf(`${location(node, v)}`) = $pts")
      pts
    } catch {
      case _: IllegalStateException =>
        logger.warn(s"`ptsOf` catches IllegalStateException ${location(node, v)}")
        Set.empty
      case _: StackOverflowError =>
        // TODO: handle back edge of basic block
        logger.warn(s"`ptsOf` catches StackOverflowError ${location(node, v)}")
        Set.empty
    }
  }

  override def clear(): Unit = {
    cache1.invalidateAll()
    cache2.invalidateAll()
  }

  private def isBackEdge(env: Env): Boolean = {
    // because the `order` is the topological order of intra-procedural bbCfg
    // so we just compare the BBs in the same method of env.m
    env.walk.filter(_.m == env.m).exists(prev => env.bb.order > prev.order)
  }

  private def findSideEffectsOn(env: Env, name: String): List[SideEffectEnv] = {
    import env.*
    val blockSummary      = funSummary.blockSummaries.getOrElse(bb, BlockSummary.empty)
    val objectSideEffects = blockSummary.propertyWriteCache.get(name)
    val arraySideEffects  = blockSummary.arrayWriteCache.get(name)
    val sideEffects       = objectSideEffects ++ arraySideEffects
    sideEffects.toList.map(sideEffect => SideEffectEnv(name, sideEffect, env.copy(walk = Set.empty)))
  }

  private def evalVariable(env: Env, name: String): Result = {
    if (isConstantVariable(name)) {
      val pts = constantTable.get(ConstantVariable(name)).toSet
      if (pts.isEmpty) return (Set(DummyObject(name)), List.empty)
      else return (pts, List.empty)
    }
    val currentSideEffects = findSideEffectsOn(env, name)
    val (pts, backwardSideEffects) =
      try {
        if (isBackEdge(env)) (Set.empty[SymbolicValue], List.empty)
        else {
          val _env = env.copy(walk = env.walk + env.bb)
          val key  = (_env.bb, name)
          val result = cache2.getOrElseUpdate(
            (key, _env.partialEval), {
              import _env.*
              val bbSummary = funSummary.blockSummaries.getOrElse(bb, BlockSummary.empty)
              val (pts, sideEffects) = bbSummary.dataflow.get(name) match {
                case Some(sv) =>
                  val recursiveName = if (isRecursive(name, sv)) Some(name) else None
                  evalSym(_env, sv, recursiveName)
                case None =>
                  // backward if there is no entry in the dataflow
                  backward(_env, name)
              }
              // create a dummy value for unresolved variable
              if (pts.isEmpty)
                (Set(DummyObject(name)), sideEffects)
              else
                (pts, sideEffects)
            }
          )
          result
        }
      } catch {
        case _: IllegalStateException =>
          logger.warn("`evalVariable` catches IllegalStateException")
          (Set.empty[SymbolicValue], List.empty)
      }
    val sideEffects = currentSideEffects ++ backwardSideEffects
    val propagation = applySideEffects(env, name, pts, sideEffects)
    (pts, propagation)
  }

  private def applySideEffect(env: Env, value: SymbolicValue, sideEffectEnv: SideEffectEnv): Unit = {
    sideEffectEnv.sideEffect match {
      case wrapper: PropertyWriteWrapper =>
        value match {
          case obj: (SymbolicObject | DummyObject) =>
            val fields = evalSym(env, wrapper.key, None)._1.extract[ConstantValue]
            fields.foreach(field => obj.getConcrete.put(field.toString, wrapper.data))
          case _ =>
        }
      case arraySideEffect: ArraySideEffect =>
        value match {
          case array: (SymbolicArray | DummyObject) =>
            arraySideEffect match {
              case arrayPush: ArrayPush =>
                val index = array.getConcrete.keys.size.toString
                array.getConcrete.put(index, arrayPush.value)
              case wrapper: ArrayWriteWrapper =>
                val fields = evalSym(env, wrapper.key, None)._1.extract[ConstantValue]
                fields.foreach(field => array.getConcrete.put(field.toString, wrapper.data))
            }
          case _ =>
        }
    }
  }

  private def applySideEffect(env: Env, sideEffectEnv: SideEffectEnv): Unit = {
    val values = evalVariable(sideEffectEnv.env, sideEffectEnv.name)._1
    values.foreach(value => applySideEffect(env, value, sideEffectEnv))
  }

  private def applySideEffects(
    env: Env,
    name: String,
    values: Set[SymbolicValue],
    sideEffectEnvs: List[SideEffectEnv]
  ): List[SideEffectEnv] = {
    val groups = sideEffectEnvs.groupBy(_.name == name)
    groups
      .get(true)
      .foreach(matchedSideEffects =>
        matchedSideEffects
          .foreach(sideEffect => values.foreach(value => applySideEffect(env, value, sideEffect)))
      )
    // unmatched side effects need to be propagated to its caller
    groups.getOrElse(false, List.empty)
  }

  /** @param env
    *   the context in which the [[sv]] is located
    * @param sv
    *   the symbolic value that needs to be evaluated
    * @param recursiveName
    *   variable name that recursively appear in [[sv]]
    */
  private def evalSym(env: Env, sv: SymbolicValue, recursiveName: Option[String]): Result = {
    import env.*
    sv match {
      case cv: ConstantValue => (Set(cv), List.empty)
      case mapLike: (SymbolicObject | SymbolicArray | DummyObject) =>
        mapLike.getConcrete.mapValuesInPlace { (key, value) =>
          val (values, sideEffects) = evalSym(env, value, recursiveName) // TODO: collect side effect
          if (values.isEmpty) value
          else if (values.size > 1) MultiValue(values.toList)
          else values.head
        }
        (Set(mapLike), List.empty)
      case sv: UntypedVariable =>
        sv.name match {
          case StringLiteral(name) =>
            val (pts, sideEffects) = recursiveName match {
              case Some(recursive) if recursive == name => backward(env, name)
              case _                                    => evalVariable(env, name)
            }
            (pts, sideEffects)
          case _ =>
            // TODO: handle variable variables
            (Set.empty, List.empty)
        }
      case adf: UntypedArrayFetch =>
        val (bases, baseSideEffects)    = evalSymTo[SymbolicArray | DummyObject](env, adf.base, recursiveName)
        val (indexes, indexSideEffects) = evalSymTo[ConstantValue](env, adf.key, recursiveName)
        val sideEffects                 = baseSideEffects ++ indexSideEffects
        var pts = for {
          base  <- bases
          index <- indexes
          value <- base.get(index.toString)
        } yield value
        // taint source of php => .* pattern
        pts =
          if (partialEval && pts.isEmpty) Set(ValueSetResult.dotPatternSym)
          else pts
        (pts, sideEffects)
      case pf: UntypedPropertyFetch =>
        val (bases, baseSideEffects)   = evalSymTo[SymbolicObject | DummyObject](env, pf.base, recursiveName)
        val (fields, fieldSideEffects) = evalSymTo[ConstantValue](env, pf.key, recursiveName)
        val sideEffects                = baseSideEffects ++ fieldSideEffects
        val pts = for {
          base  <- bases
          field <- fields
          value <- base.get(field.toString)
        } yield value
        (pts, sideEffects)
      case sc: UntypedStringConcat => evalStringConcat(env, sc.lhs, sc.rhs, recursiveName)
      case multiValue: MultiValue =>
        val all         = multiValue.values.map(v => evalSym(env, v, recursiveName))
        val pts         = all.flatMap(_._1).toSet
        val sideEffects = all.flatMap(_._2)
        (pts, List.empty)
      case aak: ArrayAllKeys =>
        val (bases, sideEffects) = evalSymTo[SymbolicArray | DummyObject](env, aak.base, recursiveName)
        val pts = bases.flatMap(base =>
          val concreteKeys = base.getConcrete.keys.map(key => StringLiteral(key))
          val symbolicKeys = base.getSymbolic.keys
          concreteKeys ++ symbolicKeys
        )
        (pts, sideEffects)
      case aav: ArrayAllValues =>
        val (bases, sideEffects) = evalSymTo[SymbolicArray | DummyObject](env, aav.base, recursiveName)
        val pts = bases.flatMap(base =>
          val concreteValues = base.getConcrete.values
          val symbolicValues = base.getSymbolic.values
          concreteValues ++ symbolicValues
        )
        (pts, sideEffects)
      case ue: UntypedEqual       => evalUntypedEqual(env, ue, recursiveName)
      case uln: UntypedLogicalNot => evalUntypedLogicalNot(env, uln, recursiveName)
      case ula: UntypedLogicalAnd => evalLogicalBinOpSym(env, ula.lhs, ula.rhs, recursiveName, isAnd = true)
      case ulo: UntypedLogicalOr  => evalLogicalBinOpSym(env, ulo.lhs, ulo.rhs, recursiveName, isAnd = false)
      case ua: UntypedAdd         => evalIntBinOpSym(env, ua.lhs, ua.rhs, recursiveName, isAdd = true)
      case us: UntypedSub         => evalIntBinOpSym(env, us.lhs, us.rhs, recursiveName, isAdd = false)
      case _ =>
        (Set.empty, List.empty)
    }
  }

  /** wrapper for [[evalSym]] with filter operation
    */
  private def evalSymTo[T: ClassTag](
    env: Env,
    sv: SymbolicValue,
    recursiveName: Option[String]
  ): (Set[T], List[SideEffectEnv]) = {
    val (syms, sideEffects) = evalSym(env, sv, recursiveName)
    val targetSyms          = syms.collectAll[T].toSet
    (targetSyms, sideEffects)
  }

  /** wrapper for [[evalSym]] that omits the dummy object
    */
  private def evalSymOmitDummy(
    env: Env,
    sv: SymbolicValue,
    recursiveName: Option[String]
  ): (Set[SymbolicValue], List[SideEffectEnv]) = {
    val (syms, sideEffects) = evalSym(env, sv, recursiveName)
    val cleanSyms           = syms.filterNot(_.is[DummyObject])
    (cleanSyms, sideEffects)
  }

  /** wrapper for [[evalSym]] with cast & filter operation
    *
    * string/numeric/comparison operator in PHP will do cast operation to transform the type of the variable
    */
  private def evalSymCastTo[T: ClassTag](
    env: Env,
    sv: SymbolicValue,
    recursiveName: Option[String],
    castOperator: SymbolicValue => SymbolicValue
  ): (Set[T], List[SideEffectEnv]) = {
    // remove dummy object because it may affect the cast operator
    val (syms, sideEffects) = evalSymOmitDummy(env, sv, recursiveName)
    val targetSyms          = syms.map(castOperator).collectAll[T].toSet
    (targetSyms, sideEffects)
  }

  private def evalStringConcat(
    env: Env,
    lhs: SymbolicValue,
    rhs: SymbolicValue,
    recursiveName: Option[String]
  ): Result = {
    def evalString(sv: SymbolicValue): (Set[String], Boolean, List[SideEffectEnv]) = {
      val (constants, sideEffects) = evalSymTo[ConstantValue](env, sv, recursiveName)
      if (constants.nonEmpty)
        (constants.map(_.toString), false, sideEffects)
      else {
        if (env.partialEval)
          (Set(ValueSetResult.dotPattern), true, sideEffects)
        else
          (Set(""), true, sideEffects)
      }
    }

    val (lefts, isLeftEmpty, leftSideEffects)    = evalString(lhs)
    val (rights, isRightEmpty, rightSideEffects) = evalString(rhs)
    val sideEffects                              = leftSideEffects ++ rightSideEffects
    val pts =
      if (isLeftEmpty && isRightEmpty && !env.partialEval) Set.empty[SymbolicValue]
      else {
        for {
          left  <- lefts
          right <- rights
        } yield StringLiteral(left + right)
      }
    (pts, sideEffects)
  }

  private def evalIntBinOpSym(
    env: Env,
    lhs: SymbolicValue,
    rhs: SymbolicValue,
    recursiveName: Option[String],
    isAdd: Boolean
  ): Result = {
    val (lefts, leftSideEffects)   = evalSymCastTo[IntLiteral](env, lhs, recursiveName, SymCast.toInt)
    val (rights, rightSideEffects) = evalSymCastTo[IntLiteral](env, rhs, recursiveName, SymCast.toInt)
    val sideEffects                = leftSideEffects ++ rightSideEffects
    val pts: Set[SymbolicValue] = for {
      left  <- lefts
      right <- rights
      value = if (isAdd) left.value + right.value else left.value - right.value
    } yield IntLiteral(value)
    (pts, sideEffects)
  }

  private def evalUntypedEqual(env: Env, ue: UntypedEqual, recursiveName: Option[String]): Result = {
    type CompareType = IntLiteral | StringLiteral | BoolLiteral

    val (lefts, leftSideEffects)   = evalSymTo[CompareType](env, ue.lhs, recursiveName)
    val (rights, rightSideEffects) = evalSymTo[CompareType](env, ue.rhs, recursiveName)

    val sideEffects = leftSideEffects ++ rightSideEffects

    val pts: Set[SymbolicValue] = for {
      left  <- lefts
      right <- rights
    } yield (left, right) match {
      case (IntLiteral(lv), IntLiteral(rv))       => BoolLiteral(lv == rv)
      case (StringLiteral(lv), StringLiteral(rv)) => BoolLiteral(lv == rv)
      case (BoolLiteral(lv), BoolLiteral(rv))     => BoolLiteral(lv == rv)
      case _                                      => BoolLiteral(false)
    }

    (pts, sideEffects)
  }

  private def evalUntypedLogicalNot(env: Env, un: UntypedLogicalNot, recursiveName: Option[String]): Result = {
    val (values, sideEffects)   = evalSymCastTo[BoolLiteral](env, un.value, recursiveName, SymCast.toBool)
    val pts: Set[SymbolicValue] = values.map(x => BoolLiteral(!x.value))
    (pts, sideEffects)
  }

  private def evalLogicalBinOpSym(
    env: Env,
    lhs: SymbolicValue,
    rhs: SymbolicValue,
    recursiveName: Option[String],
    isAnd: Boolean
  ): Result = {
    val (lefts, leftSideEffects)   = evalSymCastTo[BoolLiteral](env, lhs, recursiveName, SymCast.toBool)
    val (rights, rightSideEffects) = evalSymCastTo[BoolLiteral](env, rhs, recursiveName, SymCast.toBool)
    val sideEffects                = leftSideEffects ++ rightSideEffects
    val pts: Set[SymbolicValue] = for {
      left  <- lefts
      right <- rights
      value = if (isAnd) left.value && right.value else left.value || right.value
    } yield BoolLiteral(value)
    (pts, sideEffects)
  }

  private def backward(env: Env, name: String): Result = {
    import env.*

    def getPredsOf(bb: DefaultBasicBlock): List[DefaultBasicBlock] = {
      val rawPredBBs = bbCfg.getPredsOf(bb)
      rawPredBBs
        .flatMap(pred =>
          if (pred.order < bb.order) List(pred)
          else {
            // in this case, pred might be a conditional judgment for the for loop
            val peeks = bbCfg.getPredsOf(pred)
            if (peeks.exists(_.order < bb.order)) peeks
            else List.empty
          }
        )
        .collectAll[DefaultBasicBlock]
        .toList
    }

    val predBBs = bbCfg.getPredsOf(bb)
    predBBs match {
      case Nil =>
        // reach the entry basic block of this method
        traceCaller(env, name)
      case _ =>
        val all         = predBBs.map(predBB => evalVariable(env.copy(bb = predBB.as[DefaultBasicBlock]), name))
        val pts         = all.flatMap(_._1).toSet
        val sideEffects = all.flatMap(_._2)
        (pts, sideEffects)
    }
  }

  private val magicMethods = Map("__call" -> 1, "__callStatic" -> 1)

  private def traceCaller(env: Env, name: String): Result = {
    def getCallsitesOf(method: Method): Set[Call] = {
      val universal = NoResolve.getMethodCallsites(method).collectAll[Call].toSet
      env.pathCallGraph match {
        case Some(callgraph) =>
          callgraph.get(method) match {
            case Some(callsite) =>
              if (universal.contains(callsite)) Set(callsite)
              else universal
            case None => universal
          }
        case None => universal
      }
    }

    def enterCaller(callsite: Call, parameterIndex: Integer): Result = {
      val caller = callsite.method
      logger.info(s"`ptsOf` enter caller `${caller.name} @ ${caller.filename}` for variable `$name`")
      val bbCfg = DefaultBBCfg.create(caller, unrolling = true)
      // find the corresponding argument in callsite
      callsite.args.lift(parameterIndex) match {
        case Some(arg) =>
          val _env = Env(
            caller,
            bbCfg,
            FunSummary.create(caller),
            bbCfg.bbOf(callsite),
            env.partialEval,
            isInitMethod(caller),
            env.walk,
            env.pathCallGraph
          )
          evalVariable(_env, translate(arg).toString)
        case None => (Set.empty, List.empty)
      }
    }

    env.funSummary.parameters.indexOf(name) match {
      case -1 =>
        // avoid infinite recursion
        if (isStaticField(name) && !env.isInInitMethod)
          (enterInitialSetupPhase(env, name), List.empty)
        else
          (Set.empty, List.empty)
      case index @ _ =>
        // variable is the parameter of this method
        val callsites = getCallsitesOf(env.m)
        // handle magic method __call and __callStatic
        val all =
          if (magicMethods.contains(env.m.name) && index + 1 == magicMethods(env.m.name)) {
            callsites.map(callsite =>
              if (callsite.name == env.m.name) enterCaller(callsite, index)
              else {
                val pts = Set(StringLiteral(callsite.name))
                (pts, List.empty)
              }
            )
          } else {
            callsites.map(callsite => enterCaller(callsite, index))
          }
        val pts         = all.flatMap(_._1)
        val sideEffects = all.flatMap(_._2).toList
        (pts, sideEffects)
    }
  }

  /** Enter the summary of the program initialization phase, such as the assignment of static members of class
    */
  private def enterInitialSetupPhase(env: Env, name: String): Set[SymbolicValue] = {
    // $global_var = "global_var"; // scope of <global> method
    // class MyClass {
    //    private static $name = "name"; // scope of <clinit> method
    // }
    val clinits = env.m.file.method.filter(isInitMethod)
    clinits
      .flatMap(m =>
        val bbCfg = DefaultBBCfg.create(m, unrolling = true)
        val newEnv = Env(
          m,
          bbCfg,
          FunSummary.create(m),
          bbCfg.exit,
          env.partialEval,
          isInInitMethod = true,
          env.walk,
          env.pathCallGraph
        )
        evalVariable(newEnv, name)._1
      )
      .toSet
  }

  private def buildConstantTable(): ConstantTable = {
    val table   = ConstantTable.empty
    val defines = cpg.call("define").filter(c => c.receiver.isEmpty && c.argument.size >= 2)
    defines.foreach(define =>
      (define.argument(1), define.argument(2)) match {
        case (arg1: Literal, arg2: Literal) if arg1.isStr =>
          val name  = arg1.getString
          val value = arg2.toSymbol
          table += ConstantVariable("<global>::" + name) -> value
        case _ =>
      }
    )
    table
  }

  private def isConstantVariable(name: String): Boolean = {
    isStaticField(name) && name.startsWith("<global>")
  }

  /** It is used to determine whether the accessed variable name is [[StaticFieldVar]]
    */
  private def isStaticField(name: String): Boolean = name.contains("::")

  private def isInitMethod(m: Method): Boolean = m.name == "<clinit>"

  private def isRecursive(left: String, sv: SymbolicValue): Boolean = {
    sv match {
      case sv: UntypedVariable =>
        sv.name match {
          case StringLiteral(value) => value == left
          case _                    => false
        }
      case adf: UntypedArrayFetch =>
        isRecursive(left, adf.base) || isRecursive(left, adf.key)
      case pf: UntypedPropertyFetch =>
        isRecursive(left, pf.base) || isRecursive(left, pf.key)
      case sc: UntypedStringConcat =>
        isRecursive(left, sc.lhs) || isRecursive(left, sc.rhs)
      case _ => false
    }
  }
}
