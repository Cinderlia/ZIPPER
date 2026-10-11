package bee.zipper.core

import bee.zipper.core.ir.*
import io.shiftleft.codepropertygraph.generated.Languages

import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.*

class AnalysisContext(language: String = Languages.PHP) {
  val cache = new Cache()

  class Cache {
    private val cache = new ConcurrentHashMap[Any, Any]()

    def put[T](cls: Class[T], key: Object, value: Object): Unit = cache.put((cls, key), value)

    def get[T](cls: Class[T], key: Object): Option[T] = Option(cache.get((cls, key)).asInstanceOf[T])

    def remove[T](cls: Class[T], key: Object): Unit = cache.remove((cls, key))

    def clear(): Unit = cache.clear()

    def getOrElseUpdate[T](cls: Class[T], key: Object, op: => T): T = {
      val opt = Option(cache.get((cls, key)))
      opt match {
        case Some(value) => value.asInstanceOf[T]
        case None =>
          val value = op
          cache.put((cls, key), value)
          value
      }
    }
  }

  val translator: Translator = language match {
    case Languages.PHP => PHPTranslator
    case _             => PHPTranslator
  }
}
