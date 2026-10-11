package bee.zipper.util

import com.github.benmanes.caffeine.cache

import java.util.concurrent.TimeUnit

object MemoryCache {
  def mk[K, V]: cache.Cache[K, V] = {
    cache.Caffeine
      .newBuilder()
      .maximumSize(3000)
      .expireAfterWrite(3, TimeUnit.MINUTES)
      .build()
  }

  extension [K, V](c: cache.Cache[K, V]) {
    def getOrElseUpdate(key: K, op: => V): V = {
      val opt = Option(c.getIfPresent(key))
      opt match {
        case Some(value) => value
        case None =>
          val value = op
          c.put(key, value)
          value
      }
    }
  }
}
