package bee.zipper.core.analysis.model.summary

import bee.zipper.api.solver.sym.extend.{ObjectSideEffect, SymbolicObject}

trait BlockSummaryBuilder {

  /** Builds a BlockSummary using the provided previous object cache and previous property write cache.
    *
    * @param prevObjectCache
    *   an Iterable of (String, SymbolicObject) tuples representing the previous object cache
    * @param prevPropWriteCache
    *   an Iterable of (String, PropertyWriteWrapper) tuples representing the previous property write cache
    * @return
    *   a BlockSummary object
    */
  def build(
    prevObjectCache: Iterable[(String, SymbolicObject)],
    prevPropWriteCache: Iterable[(String, ObjectSideEffect)]
  ): BlockSummary
}
