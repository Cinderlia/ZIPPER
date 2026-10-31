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

/** Depth/cycle-safe rendering of symbolic structures.
  *
  * A symbolic array can contain itself (`$this->posts` containing `$this->posts`), so plain `Map.toString` recurses
  * forever. Rendering is bounded by `maxDepth` (default 8, configurable through the system property
  * `zipper.symbolic.print.depth`) and stops at already visited objects.
  */
object SymbolicPrint {
  private val depth = new ThreadLocal[Integer] { override def initialValue(): Integer = Integer.valueOf(0) }
  private val seen = new ThreadLocal[java.util.IdentityHashMap[AnyRef, java.lang.Boolean]] {
    override def initialValue(): java.util.IdentityHashMap[AnyRef, java.lang.Boolean] =
      new java.util.IdentityHashMap[AnyRef, java.lang.Boolean]()
  }

  def maxDepth: Int = Integer.getInteger("zipper.symbolic.print.depth", 8).intValue()

  def render(map: SymbolicMap): String = {
    if (depth.get().intValue() >= maxDepth) return "..."
    if (seen.get().containsKey(map)) return "<cycle>"
    seen.get().put(map, java.lang.Boolean.TRUE)
    depth.set(Integer.valueOf(depth.get().intValue() + 1))
    try {
      val kind = map match {
        case obj: SymbolicObject => s"obj: ${obj.getTypeName}"
        case _                   => "array"
      }
      val entries = map.getConcrete.map { case (key, value) => s"$key -> ${renderValue(value)}" }.mkString(", ")
      s"$kind { $entries }"
    } finally {
      depth.set(Integer.valueOf(depth.get().intValue() - 1))
      seen.get().remove(map)
    }
  }

  private def renderValue(value: SymbolicValue): String = value match {
    case nested: SymbolicMap => render(nested)
    case other =>
      try other.toString
      catch { case _: StackOverflowError => "..." }
  }
}

class SymbolicObject(private var typeName: String) extends SymbolicMap {
  def getTypeName: String = typeName

  def setTypeName(typeName: String): Unit = this.typeName = typeName

  override def toString: String = SymbolicPrint.render(this)
}

class SymbolicArray extends SymbolicMap {
  override def toString: String = SymbolicPrint.render(this)
}
