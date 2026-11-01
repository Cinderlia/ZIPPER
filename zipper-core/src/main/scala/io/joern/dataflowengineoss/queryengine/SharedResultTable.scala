package io.joern.dataflowengineoss.queryengine

/** Bounded LRU table used to share dataflow engine results across probe searches.
  *
  * Entries are keyed by [[TaskFingerprint]] (node + call stack + call depth) and hold the results computed for that
  * task. Entries are kept in access order: a hit moves the entry to the end, and when the table is full the least
  * recently used entry is evicted first.
  */
final class SharedResultTable(maxEntries: Int) {
  private val map = scala.collection.mutable.LinkedHashMap.empty[TaskFingerprint, List[TableEntry]]

  def get(key: TaskFingerprint): Option[List[TableEntry]] = this.synchronized {
    map.get(key).map { value =>
      map.remove(key)
      map.put(key, value)
      value
    }
  }

  def put(key: TaskFingerprint, value: List[TableEntry]): Unit = this.synchronized {
    map.remove(key)
    map.put(key, value)
    if (map.size > maxEntries) map.remove(map.head._1)
  }

  def clear(): Unit = this.synchronized(map.clear())

  def size: Int = this.synchronized(map.size)

  def keys: List[TaskFingerprint] = this.synchronized(map.keys.toList)

  def entries: List[(TaskFingerprint, List[TableEntry])] = this.synchronized(map.toList)

  def values: List[List[TableEntry]] = this.synchronized(map.values.toList)
}
