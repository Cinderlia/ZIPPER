package bee.zipper.core.analysis.taint

class TaintPathCluster(taintPaths: List[TaintPath]) {
  def cluster(): List[List[TaintPath]] = taintPaths.groupBy(_.sink).values.toList
}
