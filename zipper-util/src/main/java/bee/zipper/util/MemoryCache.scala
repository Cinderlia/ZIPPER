package bee.zipper.util

import com.github.benmanes.caffeine.cache

import java.util.concurrent.TimeUnit

object MemoryCache {

  /** Capacity of the memoization caches. The value-set analysis memoizes per `(basic block, variable)` state; on large
    * code bases that state space has millions of entries, so a small cache turns the recursive evaluation into an
    * exponential re-computation. Override with `-Dzipper.cache.size=N`.
    */
  private def size: Long = java.lang.Long.getLong("zipper.cache.size", 500000L).longValue()

  /** Lifetime of a cached entry. A single analysis run reuses the same entries for its whole lifetime, so the default
    * is effectively "until the run ends"; override with `-Dzipper.cache.ttl.minutes=N`.
    */
  private def ttlMinutes: Long = java.lang.Long.getLong("zipper.cache.ttl.minutes", 24L * 60L).longValue()

  def mk[K, V]: cache.Cache[K, V] = {
    val builder = cache.Caffeine.newBuilder().maximumSize(size)
    if (ttlMinutes > 0) builder.expireAfterWrite(ttlMinutes, TimeUnit.MINUTES)
    builder.build()
  }

  extension [K, V](c: cache.Cache[K, V]) {

    /** Callers re-enter the same cache while computing a value (the value-set analysis evaluates a variable through its
      * predecessors, which evaluates further variables), so the value has to be computed without holding a cache lock.
      * `computeIfAbsent` keeps the bin locked for the whole evaluation, and two caches entered in opposite orders by
      * different threads then deadlock. Computing first and storing after is safe here because every entry is a pure
      * function of the key.
      */
    def getOrElseUpdate(key: K, op: => V): V = {
      val cached = c.getIfPresent(key)
      if (cached != null) cached
      else {
        val value = op
        c.put(key, value)
        value
      }
    }
  }
}
