package bee.zipper.core.analysis.taint

import io.joern.dataflowengineoss.language.Path
import io.shiftleft.semanticcpg.language.*

object DuplicateFlowProcessor {
  def deduplicate(paths: Iterator[Path]): Iterator[Path] = deduplicateByStringSubset(paths)

  private def deduplicateByStringSubset(paths: Iterator[Path]): Iterator[Path] = {
    paths
      .groupBy { path =>
        // use node.code instead of node
        val head = path.elements.headOption.map(x => (x.code, x.file.name.headOption)).get
        val last = path.elements.lastOption.map(x => (x.code, x.file.name.headOption)).get
        (head, last)
      }
      .flatMap { case (_, list) => list.headOption }
      .iterator
  }
}
