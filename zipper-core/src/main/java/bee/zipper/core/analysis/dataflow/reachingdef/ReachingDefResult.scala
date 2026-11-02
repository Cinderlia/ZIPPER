package bee.zipper.core.analysis.dataflow.reachingdef

import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

/** Unified representation of the results of reaching-def analysis.
  *
  * The definitions of a statement are stored as a compact bit set indexed by `rankToNode` instead of a list of
  * `CfgNode`s. On large programs the materialized list representation dominates the memory usage of the analysis (a bit
  * is a hundred times smaller than a list cell), so it is only kept as a fallback for the IFDS engine.
  */
class ReachingDefResult(
  private val stmtToBits: Map[CfgNode, ReachingDefFact] = Map.empty,
  private val rankToNode: Array[CfgNode] = Array.empty,
  private val stmtToLists: Map[CfgNode, List[CfgNode]] = Map.empty
) {
  private lazy val nodeToRank: Map[CfgNode, Int] = rankToNode.iterator.zipWithIndex.toMap

  /** Whether `definition` is part of the reaching definitions of `stmt`. Testing membership in the bit set avoids
    * materializing the (potentially huge) list of definitions of `stmt`.
    */
  def reaches(stmt: CfgNode, definition: CfgNode): Boolean =
    stmtToBits.get(stmt) match {
      case Some(bits) => nodeToRank.get(definition).exists(bits.get)
      case None       => stmtToLists.get(stmt).exists(_.contains(definition))
    }

  def getReachingDefs(stmt: CfgNode): Iterator[CfgNode] =
    stmtToBits.get(stmt) match {
      case Some(bits) => bitsToNodes(bits)
      case None       => stmtToLists.getOrElse(stmt, Nil).iterator
    }

  /** Iterate the nodes whose rank is set in `bits`, in rank order. */
  private def bitsToNodes(bits: ReachingDefFact): Iterator[CfgNode] =
    new Iterator[CfgNode] {
      private var nextRank = bits.nextSetBit(0)

      override def hasNext: Boolean = nextRank >= 0

      override def next(): CfgNode = {
        if (nextRank < 0) throw new NoSuchElementException("next on empty iterator")
        val node = rankToNode(nextRank)
        nextRank = bits.nextSetBit(nextRank + 1)
        node
      }
    }

  def getReachingDefList(stmt: CfgNode): List[CfgNode] = getReachingDefs(stmt).toList
}

object ReachingDefResult {

  /** Build the result directly from the fixed point of the bit-set based analysis, without materializing lists. */
  def fromBits(stmtToBits: Map[CfgNode, ReachingDefFact], rankToNode: Array[CfgNode]): ReachingDefResult =
    new ReachingDefResult(stmtToBits = stmtToBits, rankToNode = rankToNode)

  def fromLists(stmtToReachingDefs: Map[CfgNode, List[CfgNode]]): ReachingDefResult =
    new ReachingDefResult(stmtToLists = stmtToReachingDefs)
}
