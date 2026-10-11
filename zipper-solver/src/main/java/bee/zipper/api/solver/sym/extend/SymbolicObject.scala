package bee.zipper.api.solver.sym.extend

import bee.zipper.api.solver.sym.term.{ConstantValue, SymbolicValue}

import scala.collection.mutable

/** symbolic representation of object and array
  */
trait SymbolicMap extends SymbolicValue {
  protected var concrete = mutable.Map.empty[String, SymbolicValue]

  protected var symbolic = mutable.Map.empty[SymbolicValue, SymbolicValue]

  def getConcrete: mutable.Map[String, SymbolicValue] = concrete

  def getSymbolic: mutable.Map[SymbolicValue, SymbolicValue] = symbolic

  def add(key: String, value: SymbolicValue): Unit = concrete += key -> value

  def add(key: SymbolicValue, value: SymbolicValue): Unit = {
    key match {
      case x: ConstantValue => add(x.toString, value)
      case _                => symbolic += key -> value
    }
  }

  def get(key: String): Option[SymbolicValue] = concrete.get(key)

  def get(key: SymbolicValue): Option[SymbolicValue] = {
    key match {
      case x: ConstantValue => get(x.toString)
      case _                => symbolic.get(key)
    }
  }

  override def equals(obj: Any): Boolean = {
    obj match {
      case o: SymbolicMap => concrete == o.concrete && symbolic == o.symbolic
      case _              => false
    }
  }
}

class SymbolicObject(private var typeName: String) extends SymbolicMap {
  def getTypeName: String = typeName

  def setTypeName(typeName: String): Unit = this.typeName = typeName

  override def toString: String = s"obj: $typeName $concrete"
}

class SymbolicArray extends SymbolicMap {
  override def toString: String = s"array: $concrete"
}
