package bee.zipper.util

import scala.reflect.ClassTag

object AnyExtension {
  extension (o: Any) {
    def is[T: ClassTag]: Boolean = {
      val clazz = implicitly[ClassTag[T]].runtimeClass
      clazz.isInstance(o)
    }

    def as[T]: T = o.asInstanceOf[T]

    def tryAs[T: ClassTag]: Option[T] = if (o.is[T]) Some(o.as[T]) else None
  }
}
