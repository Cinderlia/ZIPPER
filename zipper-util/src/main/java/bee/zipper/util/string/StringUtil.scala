package bee.zipper.util.string

import scala.collection.mutable
import org.apache.commons.text.similarity.JaccardSimilarity

object StringUtil {

  /** A trie node used for building a trie data structure.
    *
    * @param children
    *   a mutable map that stores the child nodes for each character in the trie
    * @param isEnd
    *   a flag indicating whether the current node represents the end of a string
    */
  class TrieNode(val children: mutable.Map[Char, TrieNode] = mutable.Map.empty, var isEnd: Boolean = false)

  /** Builds a trie data structure from a sequence of strings.
    *
    * @param strings
    *   the sequence of strings to be used for building the trie
    * @return
    *   the root node of the built trie
    */
  def buildTrie(strings: Seq[String], overrideEnd: Boolean = false): TrieNode = {
    val root   = new TrieNode
    val sorted = strings.sortBy(_.length)
    for (str <- sorted) {
      var current = root
      for (char <- str) {
        val child = current.children.getOrElseUpdate(char, new TrieNode)
        current = child
        if (overrideEnd)
          current.isEnd = false
      }
      current.isEnd = true
    }
    root
  }

  /** Gets the minimum/max set of prefix strings from a given sequence of strings.
    *
    * For example, for the input `["ABCDE", "ABCD", "ABC", "BCD", "BC"]`, the minimum output will be `["ABC", "BC"]`.
    *
    * @param strings
    *   the sequence of strings to be processed
    * @return
    *   the minimum/max set of prefix strings
    */
  def getStringSet(strings: Seq[String], max: Boolean = false): Set[String] = {
    val result = mutable.Set[String]()

    def dfs(node: TrieNode, path: Seq[Char]): Unit = {
      if (node.isEnd) {
        result += path.mkString
        return
      }
      for ((char, child) <- node.children) {
        dfs(child, path :+ char)
      }
    }

    val root = buildTrie(strings, max)
    dfs(root, Seq.empty)
    result.toSet
  }

  /** Clusters a sequence of strings based on string similarity.
    *
    * @param strings
    *   the sequence of strings to be clustered
    * @param threshold
    *   the minimum similarity threshold for two strings to be considered in the same cluster (default is 0.9)
    * @return
    *   a sequence of sets, where each set represents a cluster of similar strings
    */
  def cluster(strings: Seq[String], threshold: Double = 0.9): Seq[Set[String]] = {
    val jaroWink = new JaccardSimilarity()

    def similarity(s1: String, s2: String): Double = {
      jaroWink.apply(s1, s2)
    }

    val clusters = mutable.ListBuffer.empty[Set[String]]
    val visited  = mutable.Set.empty[String]
    for (s <- strings) {
      if (!visited.contains(s)) {
        val cluster = mutable.Set.empty[String]
        val queue   = mutable.Queue(s)
        visited += s
        while (queue.nonEmpty) {
          val curr = queue.dequeue()
          cluster += curr
          for (other <- strings if !visited.contains(other) && similarity(curr, other) >= threshold) {
            queue += other
            visited += other
          }
        }
        clusters += cluster.toSet
      }
    }
    clusters.toSeq
  }

  /** Deduplicates a dataset by removing similar elements based on a given similarity threshold.
    *
    * @param dataset
    *   the dataset to be deduplicated
    * @param stringify
    *   a function that converts an element of the dataset to a string representation
    * @param threshold
    *   the minimum similarity threshold for two elements to be considered duplicates (default is 0.9)
    * @return
    *   a set of unique elements from the dataset
    */
  def deduplicateBySimilarity[T](dataset: Iterable[T], stringify: T => String, threshold: Double = 0.9): Set[T] = {
    val stringToData = dataset.map(data => stringify(data) -> data).toMap
    val clusters     = cluster(stringToData.keys.toSeq, threshold)
    val picked = clusters.flatMap(x => {
      if (x.isEmpty) None
      else if (x.size == 1) Some(x.head)
      else Some(x.minBy(_.length))
    })
    picked.flatMap(x => stringToData.get(x)).toSet
  }

  /** Deduplicates a dataset by removing elements that are subsets of other elements.
    *
    * @param dataset
    *   the dataset to be deduplicated
    * @param stringify
    *   a function that converts an element of the dataset to a string representation
    * @return
    *   a set of unique elements from the dataset
    */
  def deduplicateBySubset[T](dataset: Iterable[T], stringify: T => String): Set[T] = {
    if (dataset.size == 1) return dataset.toSet
    val stringToData = dataset.map(data => stringify(data) -> data).toMap
    val result       = mutable.ListBuffer.empty[String]
    val root         = buildTrie(stringToData.keys.toSeq)
    val queue        = mutable.Queue[(TrieNode, Seq[Char])]((root, Seq.empty))
    while (queue.nonEmpty) {
      val (node, path) = queue.dequeue()
      if (node.isEnd && node.children.isEmpty) {
        result += path.mkString
      }
      for ((char, child) <- node.children) {
        queue.enqueue((child, path :+ char))
      }
    }
    result.flatMap(x => stringToData.get(x)).toSet
  }
}

object StringUtilExample extends App {
  val x = StringUtil.getStringSet(List("ABCDE", "ABCD", "ABC", "BCD", "BC", "EF", "E"), true)
  println(x)

  val y = StringUtil.deduplicateBySimilarity(List("ABC", "AB", "ABCD", "ABCDEFGTTT"), x => x)
  println(y)

  val z = StringUtil.deduplicateBySubset(List("ABCDE", "ABCD", "ABC", "BCD", "BC", "EF"), x => x)
  println(z)
}
