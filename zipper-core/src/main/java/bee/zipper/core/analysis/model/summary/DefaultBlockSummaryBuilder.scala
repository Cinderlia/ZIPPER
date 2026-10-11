package bee.zipper.core.analysis.model.summary

import bee.zipper.api.solver.sym.extend.*
import bee.zipper.api.solver.sym.term.*
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.bbcfg.BasicBlock
import bee.zipper.core.ir.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.joern.php2cpg.parser.Domain.PhpOperators
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Generates data flow summaries for basic blocks in a method.
  *
  * @param methodProcessor
  *   The method processor used to process the method containing the basic block.
  * @param depth
  *   The current call depth of the summary generation process.
  * @param maxDepth
  *   The maximum allowed call depth for the summary generation process.
  */
class DefaultBlockSummaryBuilder(bb: BasicBlock, methodProcessor: MethodProcessor, depth: Int, maxDepth: Int)(implicit
  ctx: AnalysisContext
) extends BlockSummaryBuilder
    with CpgNodeExecutor[Unit] {
  import ctx.translator.translate
  import methodProcessor.*

  /** variable name to assigned data */
  private val dataflow                           = mutable.Map.empty[String, SymbolicValue]
  private val globalDefines                      = mutable.Set.empty[String]
  private var returnValue: Option[SymbolicValue] = None
  private val objectCache                        = mutable.MultiDict.empty[String, SymbolicObject]
  private val propertyWriteCache                 = mutable.MultiDict.empty[String, ObjectSideEffect]
  private val arrayWriteCache                    = mutable.MultiDict.empty[String, ArraySideEffect]

  /** Builds the block summary by executing each node in the basic block
    */
  override def build(
    prevObjectCache: Iterable[(String, SymbolicObject)],
    prevPropWriteCache: Iterable[(String, ObjectSideEffect)]
  ): BlockSummary = {
    objectCache ++= prevObjectCache
    propertyWriteCache ++= prevPropWriteCache
    bb.nodes.foreach(node => execute(node, ()))
    BlockSummary(dataflow.toMap, globalDefines.toSet, returnValue, objectCache, propertyWriteCache, arrayWriteCache)
  }

  /** Adds a symbolic value to the appropriate cache based on its type.
    */
  private final def add(name: String, value: SymbolicValue): Unit = {
    value match {
      case obj: SymbolicObject =>
        objectCache += name -> obj
        dataflow += name    -> value
      case sideEffect: ObjectSideEffect =>
        propertyWriteCache += name -> sideEffect
      case sideEffect: ArraySideEffect =>
        arrayWriteCache += name -> sideEffect
      case _ =>
        dataflow += name -> value
    }
  }

  override protected def executeOperatorCall(tmpVarName: String, call: Call, ctx: Unit): Boolean = {
    call.name match {
      // executeBasicBinary
      case Operators.plus | Operators.minus | Operators.equals | Operators.notEquals | Operators.logicalAnd |
          Operators.logicalOr =>
        val lhsOption = call.argumentOption(1).map(valueOf)
        val rhsOption = call.argumentOption(2).map(valueOf)
        if (lhsOption.isDefined && rhsOption.isDefined) {
          val lhs = lhsOption.get
          val rhs = rhsOption.get
          val value = call.name match {
            case Operators.plus       => UntypedAdd(lhs, rhs)
            case Operators.minus      => UntypedSub(lhs, rhs)
            case Operators.equals     => UntypedEqual(lhs, rhs)
            case Operators.notEquals  => UntypedLogicalNot(UntypedEqual(lhs, rhs))
            case Operators.logicalAnd => UntypedLogicalAnd(lhs, rhs)
            case Operators.logicalOr  => UntypedLogicalOr(lhs, rhs)
          }
          add(tmpVarName, value)
        }
      case Operators.logicalNot =>
        val argOption = call.argumentOption(1).map(valueOf)
        if (argOption.isDefined) {
          val arg   = argOption.get
          val value = UntypedLogicalNot(arg)
          add(tmpVarName, value)
        }
      // executeBasicTernary
      case Operators.conditional =>
        val trueBranchOption  = call.argumentOption(2)
        val falseBranchOption = call.argumentOption(3)
        if (trueBranchOption.isDefined && falseBranchOption.isDefined) {
          val trueValue  = valueOf(trueBranchOption.get)
          val falseValue = valueOf(falseBranchOption.get)
          val value      = MultiValue(trueValue, falseValue)
          add(tmpVarName, value)
        }
      // executeMemoryAccess
      case Operators.alloc =>
        val obj = SymbolicObject(call.typeFullName)
        add(tmpVarName, obj)
      case Operators.indexAccess =>
        val base = valueOf(call.argument(1))
        call.argumentOption(2).foreach { arg2 =>
          val index = valueOf(arg2)
          val valueOption = base match {
            case array: SymbolicArray => array.get(index.toString)
            case _                    => Some(UntypedArrayFetch(base, index))
          }
          valueOption.foreach(value => add(tmpVarName, value))
        }
      case Operators.fieldAccess =>
        val base = valueOf(call.argument(1))
        call.argumentOption(2).foreach { arg2 =>
          val field = valueOf(arg2)
          val valueOption = base match {
            case obj: SymbolicObject =>
              field match {
                case StringLiteral(sf) => obj.get(sf)
                case _                 => None
              }
            case sv: SymbolicValue => Some(UntypedPropertyFetch(sv, field))
          }
          valueOption.foreach(value => add(tmpVarName, value))
        }
      // executeAssignment
      case Operators.assignment => executeAssignment(tmpVarName, call)
      case _                    => return false
    }
    true
  }

  override protected def executeLanguageSpecificFunction(tmpVarName: String, call: Call, ctx: Unit): Boolean = {
    call.name match {
      // executePhpBuiltin
      case PhpOperators.concatOp =>
        val lhs = translate(call.argument(1))
        val rhs = translate(call.argument(2))

        def impl(le: Expr, re: Expr): SymbolicValue = {
          val left  = valueOf(le)
          val right = valueOf(re)
          if (left.is[ConstantValue] && right.is[ConstantValue]) StringLiteral(left.toString + right.toString)
          else UntypedStringConcat(left, right)
        }

        val value = impl(lhs, rhs)
        add(tmpVarName, value)
      case PhpOperators.encaps =>
        val argValues = call.argument.map(valueOf).toList
        val value     = UntypedStringConcat(argValues)
        add(tmpVarName, value)
      case "array" if call.argument.isEmpty =>
        // array creation point
        val arr = new SymbolicArray
        add(tmpVarName, arr)
      case "key" if call.methodFullName == "Iterator.key" =>
        call.receiver.headOption match {
          case Some(receiver) =>
            val value = ArrayAllKeys(valueOf(receiver))
            add(tmpVarName, value)
          case None =>
        }
      case "current" if call.methodFullName == "Iterator.current" =>
        // not precise. it should build a relation between key and value
        call.receiver.headOption match {
          case Some(receiver) =>
            val value = ArrayAllValues(valueOf(receiver))
            add(tmpVarName, value)
          case None =>
        }
      case "array_push" =>
        val lhsOption = call.argumentOption(1).map(valueOf)
        val rhsOption = call.argumentOption(2).map(valueOf)
        if (lhsOption.isDefined && rhsOption.isDefined) {
          val base  = lhsOption.get
          val value = rhsOption.get
          val name  = translate(call.argument(1)).toString
          add(name, ArrayPush(base, value))
        }
      case _ => return false
    }
    true
  }

  override protected def executeReturn(tmpVarName: String, ret: Return, unused: Unit): Unit = {
    val arguments = ret.argumentOut.collectAll[CfgNode]
    arguments.headOption match {
      case Some(argument) =>
        returnValue = Some(valueOf(argument))
      case _ =>
    }
  }

  private def executeAssignment(unused: String, call: Call): Unit = {
    def impl(assignment: Call, left: Expr, value: SymbolicValue): Unit = {
      left match {
        case v: (RealVar | StaticFieldVar) =>
          add(v.toString, value)
        case ifa: InstanceFieldAccess =>
          val field = valueOf(ifa.field)
          objOf(ifa.base) match {
            case base: SymbolicObject =>
              base.add(field, value)
            case base: UntypedVariable =>
              val baseName = ifa.base.toString
              add(baseName, base)                               // add to dataflow
              add(baseName, PropertyWriteWrapper(field, value)) // add to propertyWriteCache
          }
        case aa: ArrayAccess =>
          val index = valueOf(aa.index)
          valueOf(aa.base) match {
            case base: SymbolicArray => base.add(index, value)
            case base: SymbolicValue =>
              val baseName = aa.base.toString
              add(baseName, base)             // add to dataflow
              ArrayWriteWrapper(index, value) // TODO: store [[ArrayDimWrite]] in somewhere
          }
        case _ =>
      }
    }
    (call.argumentOption(1), call.argumentOption(2)) match {
      case (Some(target), Some(source)) =>
        impl(call, translate(target), valueOf(source))
      case _ =>
    }
  }

  override protected def executeLiteral(tmpVarName: String, literal: Literal, unused: Unit): Unit = {
    add(tmpVarName, literal.toSymbol)
  }

  override protected def executeBlock(tmpVarName: String, prev: CfgNode, unused: Unit): Unit = {
    val value = valueOf(translate(prev))
    add(tmpVarName, value)
  }

  override protected def executeFieldIdentifier(tmpVarName: String, id: FieldIdentifier, unused: Unit): Unit = {
    val value = StringLiteral(id.code)
    add(tmpVarName, value)
  }

  /** Executes an unhandled function call by recursively generating summaries for the callees and merging their results.
    */
  override protected def executeUnhandledCall(tmpVarName: String, call: Call, unused: Unit): Unit = {
    if (depth >= maxDepth) {
      return
    }

    def getFunSummary(method: Method): FunSummary = FunSummary.create(method, depth + 1, maxDepth)

    /** transform the access of parameters in callee to arguments in caller
      */
    def transform(callsite: Call, callee: FunSummary, value: SymbolicValue): SymbolicValue = {
      def impl(value: SymbolicValue): SymbolicValue = {
        value match {
          case sv: UntypedVariable =>
            sv.name match {
              case StringLiteral(name) =>
                val x = callee.parameters.indexOf(sv.name)
                callee.parameters.indexOf(name) match {
                  case -1 => sv
                  case index @ _ =>
                    callsite.args.lift(index) match {
                      case Some(arg) => valueOf(arg)
                      case None      => sv
                    }
                }
              case _ => sv
            }
          case mapLike: (SymbolicObject | SymbolicArray) =>
            mapLike.getConcrete.mapValuesInPlace { (k, v) => impl(v) }
            mapLike
          case UntypedArrayFetch(base, key)    => UntypedArrayFetch(impl(base), impl(key))
          case ArrayWriteWrapper(key, data)    => ArrayWriteWrapper(impl(key), impl(data))
          case UntypedPropertyFetch(base, key) => UntypedPropertyFetch(impl(base), impl(key))
          case PropertyWriteWrapper(key, data) => PropertyWriteWrapper(impl(key), impl(data))
          case UntypedStringConcat(lhs, rhs)   => UntypedStringConcat(impl(lhs), impl(rhs))
          case MultiValue(values)              => MultiValue(values.map(impl))
          case _                               => value
        }
      }
      impl(value)
    }

    def merge(funSummary: FunSummary): Unit = {
      // process return values of function call
      funSummary.returnValues match {
        case x if x.isEmpty =>
        case x =>
          val returnValue = x.head
          add(tmpVarName, returnValue)
      }

      funSummary.objectCache.foreach { case (name, obj) =>
        transform(call, funSummary, obj) match {
          case x: SymbolicObject =>
            objectCache += name -> x
          case _ =>
        }
      }

      def applySideEffect(index: Int, sv: SymbolicValue): Unit = {
        call.args.lift(index) match {
          case Some(arg) =>
            val base = valueOf(arg)
            sv match {
              case pw: PropertyWriteWrapper =>
                base match {
                  case obj: SymbolicObject =>
                    obj.add(pw.key, pw.data)
                  case symVar: UntypedVariable =>
                    val baseName = translate(arg).toString
                    add(baseName, symVar)
                    add(baseName, pw)
                  case _ =>
                }
              case _ =>
            }
          case None =>
        }
      }

      funSummary.parameterSideEffects.foreach { case (index, effect) =>
        applySideEffect(index, transform(call, funSummary, effect))
      }
    }

    val callees = call.callOut.filterNot(x => x.isExternal || x.cfgFirst.head == x.methodReturn).toSet
    callees.map(getFunSummary).foreach(merge)
  }

  /** Returns the symbolic object or an untyped variable associated with the given variable.
    */
  private def objOf(v: Var): SymbolicObject | UntypedVariable = {
    val name = v.toString
    objectCache.get(v.toString) match {
      case x if x.isEmpty => UntypedVariable(StringLiteral(name))
      case x              => x.head
    }
  }

  private def valueOf(expr: Expr): SymbolicValue = {
    expr match {
      case v: (Var | StaticFieldVar) =>
        val name = v.toString
        dataflow.get(v.toString) match {
          case Some(value) => value
          case None        => UntypedVariable(StringLiteral(name))
        }
      case aa: ArrayAccess =>
        val base  = valueOf(aa.base)
        val index = valueOf(aa.index)
        base match {
          case array: SymbolicArray => array.get(index.toString).getOrElse(StringLiteral(""))
          case _                    => UntypedArrayFetch(base, index)
        }
      case ia: InstanceFieldAccess =>
        val field = valueOf(ia.field)
        objOf(ia.base) match {
          case obj: SymbolicObject =>
            field match {
              case StringLiteral(sf) => obj.get(sf).getOrElse(StringLiteral(""))
              case _                 => StringLiteral("")
            }
          case sv: SymbolicValue =>
            UntypedPropertyFetch(sv, field)
        }
    }
  }

  private def valueOf(node: CfgNode): SymbolicValue = valueOf(translate(node))
}
