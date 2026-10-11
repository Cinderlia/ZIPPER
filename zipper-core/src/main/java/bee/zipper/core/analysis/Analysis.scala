package bee.zipper.core.analysis

trait Analysis[Result] {
  def analyze(): Result
}
