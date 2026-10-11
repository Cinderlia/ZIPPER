package bee.zipper.core.analysis.taint

trait TaintSrcPropAnalysis {
  def analyze(taintPath: TaintPath): TaintSourceProperty
}
