package bee.zipper.core.analysis.taint

trait TaintAnalysis {
  def analyze(): TaintAnalysisResult
}
