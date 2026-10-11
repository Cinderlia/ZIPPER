package bee.zipper.core.analysis.dataflow.iteration.fact

import scala.collection.mutable

trait Fact

class SetFact[E] extends Fact {
  val set = mutable.Set.empty[E]

  def union(other: SetFact[E]): Unit = {
    set ++= other.set
  }

  def setTo(other: SetFact[E]): Unit = {
    set.clear()
    set ++= other.set
  }

  def copy: SetFact[E] = {
    val x = new SetFact[E]
    x.set ++= this.set
    x
  }

  override def toString: String = s"[${set.mkString(", ")}]"

  override def equals(obj: Any): Boolean = {
    obj match {
      case fact: SetFact[_] =>
        this.getClass == fact.getClass && fact.set == this.set
      case _ => false
    }
  }

  override def hashCode(): Int = set.hashCode()
}
