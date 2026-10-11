package bee.zipper.util

import bee.zipper.util.AnyExtension.is
import scala.reflect.ClassTag

object CollectionExtension {
  extension [T](collection: Iterable[T]) {
    def extract[C: ClassTag]: Iterable[C] = collection.collect { case x: C if x.is[C] => x }
  }

  extension [T](iterator: Iterator[T]) {
    def extract[C: ClassTag]: Iterator[C] = iterator.collect { case x: C if x.is[C] => x }
  }
}
