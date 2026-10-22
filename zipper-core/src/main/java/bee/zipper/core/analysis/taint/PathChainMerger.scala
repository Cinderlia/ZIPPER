package bee.zipper.core.analysis.taint

import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Merges taint paths that are built on the same chain.
  *
  * Several sinks often sit on one chain: a statement such as `$stmt->execute()` shares its provenance with the
  * `bindParam(...)` calls in the same block, because the control-flow backtracking stops at the same guard for all of
  * them. Reporting one cluster per sink duplicates that chain once per sink.
  *
  * This merger groups paths by the chain they are built on, i.e. by all nodes except the sink. Paths without a chain
  * (single-node empty sinks) are never merged: they have nothing in common but the absence of provenance. The merged
  * group keeps one path per sink, so every sink remains reported, while the chain exists only once.
  */
object PathChainMerger {

  /** Signature of the chain a path is built on; `None` for paths that consist of the sink only. */
  private def chainKey(path: TaintPath): Option[String] = {
    if (path.path.size < 2) None
    else {
      val nodes = path.path.dropRight(1).map(_.id()).mkString(":")
      Some(s"${path.kind}|$nodes")
    }
  }

  /** Groups `paths` by shared chain, preserving the order in which chains are first seen. */
  def merge(paths: List[TaintPath]): List[List[TaintPath]] = {
    val chains = mutable.LinkedHashMap.empty[String, mutable.ListBuffer[TaintPath]]
    val merged = mutable.ListBuffer.empty[List[TaintPath]]

    paths.foreach { path =>
      chainKey(path) match {
        case Some(key) => chains.getOrElseUpdate(key, mutable.ListBuffer.empty) += path
        case None      => merged += List(path)
      }
    }

    merged.toList ++ chains.values.map(group => orderBySink(group.toList)).toList
  }

  /** Orders the sinks of a chain from the deepest one to the shallowest.
    *
    * The first path names the merged cluster, so the deepest sink (the end of the chain, e.g. `execute()` instead of
    * `prepare(...)`) is used as its representative.
    */
  private def orderBySink(paths: List[TaintPath]): List[TaintPath] = {
    val reversed = paths.zipWithIndex.sortBy { case (path, index) =>
      (path.sink.lineNumber.getOrElse(0), index)
    }
    reversed.map(_._1).reverse
  }
}
