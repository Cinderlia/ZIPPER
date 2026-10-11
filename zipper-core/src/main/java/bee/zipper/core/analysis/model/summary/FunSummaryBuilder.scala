package bee.zipper.core.analysis.model.summary

trait FunSummaryBuilder {

  /** Builds a FunSummary.
    *
    * @return
    *   a FunSummary object
    */
  def build(): FunSummary
}
