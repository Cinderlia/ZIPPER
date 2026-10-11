// ZIPPER Modified [Begin]
package io.joern.dataflowengineoss.queryengine

import bee.zipper.util.string.StringUtil
import io.shiftleft.codepropertygraph.generated.language.*

object PathDeduplicate {
  def deduplicate(list: List[TableEntry], context: EngineContext): List[TableEntry] = {
    impl(list, (entry: TableEntry) => entry.path, context).toList
  }

  def deduplicate(list: Vector[ReachableByResult], context: EngineContext): Vector[ReachableByResult] = {
    val pathOf              = (entry: ReachableByResult) => entry.path
    val (partial, complete) = list.partition(x => x.partial)
    val (alias, parameter)  = partial.partition(x => x.aliasRequired)
    val part1               = impl(complete, pathOf, context).toVector
    val part2               = impl(parameter, pathOf, context).toVector
    val part3               = impl(alias, pathOf, context).toVector
    part1 ++ part2 ++ part3
  }

  /** deduplicate results within the taint analysis task
    */
  private def impl[T](list: Iterable[T], pathOf: T => Vector[PathElement], context: EngineContext): Iterable[T] = {
    val step1 = findMaxLenUniquePaths(list, pathOf)
    val iter =
      if (context.config.exploitMode) deduplicateByStringSimilarity(step1, pathOf) // exploit mode
      else deduplicateByJoernBuiltinMinimumVersion(step1.toList, pathOf)           // non-exploit mode
    iter.toVector
  }

  private def findMaxLenUniquePaths[T](list: Iterable[T], pathOf: T => Vector[PathElement]): Iterable[T] = {
    val seqToEntry: Map[String, T] = list
      .map(entry =>
        val seq = pathOf(entry).reverse.map(_.node.id.toChar).mkString // Note `reverse` call
        seq -> entry
      )
      .toMap

    // we find the max length path end with the same sink node
    val set = StringUtil.getStringSet(seqToEntry.keys.toSeq, max = true)

    set.toList.flatMap(seq => seqToEntry.get(seq))
  }

  /** The exploit mode only needs to remove duplicate paths based on similarity
    */
  private def deduplicateByStringSimilarity[T](list: Iterable[T], pathOf: T => Vector[PathElement]): Iterable[T] = {
    list
      .groupBy { result =>
        val head = pathOf(result).headOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        val last = pathOf(result).lastOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        (head, last)
      }
      .flatMap { case (_, list) =>
        StringUtil.deduplicateBySimilarity(list, (entry: T) => pathOf(entry).map(_.node.code).mkString("\n"))
      }
      .toList
  }

  /** Copy from joern. It returns the max length path of the same source-sink pair
    */
  private def deduplicateByJoernBuiltin[T](list: List[T], pathOf: T => Vector[PathElement]): Iterable[T] = {
    list
      .groupBy { result =>
        val head = pathOf(result).headOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        val last = pathOf(result).lastOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        (head, last)
      }
      .map { case (_, list) =>
        val lenIdPathPairs = list.map(x => (pathOf(x).length, x))
        val withMaxLength = (lenIdPathPairs.sortBy(_._1).reverse match {
          case Nil    => Nil
          case h :: t => h :: t.takeWhile(y => y._1 == h._1)
        }).map(_._2)

        if (withMaxLength.length == 1) {
          withMaxLength.head
        } else {
          withMaxLength.minBy { x =>
            pathOf(x)
              .map(x => (x.node.id, x.callSiteStack.map(_.id), x.visible, x.isOutputArg, x.outEdgeLabel).toString)
              .mkString("-")
          }
        }
      }
      .toList
  }

  /** Modified from joern. It returns the minimum length path of the same source-sink pair
    */
  private def deduplicateByJoernBuiltinMinimumVersion[T](
    list: List[T],
    pathOf: T => Vector[PathElement]
  ): Iterable[T] = {
    list
      .groupBy { result =>
        val head = pathOf(result).headOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        val last = pathOf(result).lastOption.map(x => (x.node, x.callSiteStack, x.isOutputArg)).get
        (head, last)
      }
      .map { case (_, group) =>
        val lenIdPathPairs = group.map(x => (pathOf(x).length, x))
        val minLength      = lenIdPathPairs.map(_._1).min

        val withMinLength = lenIdPathPairs
          .filter(_._1 == minLength)
          .map(_._2)

        if (withMinLength.length == 1) {
          withMinLength.head
        } else {
          withMinLength.minBy { x =>
            pathOf(x)
              .map(x => (x.node.id, x.callSiteStack.map(_.id), x.visible, x.isOutputArg, x.outEdgeLabel).toString)
              .mkString("-")
          }
        }
      }
      .toList
  }
}
// ZIPPER Modified [End]
