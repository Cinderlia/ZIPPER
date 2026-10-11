package bee.zipper.core.analysis.model.summary

import bee.zipper.api.solver.sym.extend.*
import bee.zipper.core.AnalysisContext
import bee.zipper.core.analysis.graph.bbcfg.BasicBlock
import io.shiftleft.codepropertygraph.generated.nodes.*

import scala.collection.{MultiDict, mutable}

/** Generates a summary for the specified method.
  *
  * @param method
  *   the method to be processed
  * @param depth
  *   the current call depth to generate the summary, default is 1
  * @param maxDepth
  *   the maximum allowed call depth to generate the summary, default is 3
  */
class DefaultFunSummaryBuilder(
  protected val method: Method,
  protected val depth: Int = 1,
  protected val maxDepth: Int = 3
)(implicit ctx: AnalysisContext)
    extends FunSummaryBuilder {
  private val methodProcessor = new MethodProcessor(method)
  import methodProcessor.*

  private val bbToSummary = mutable.Map.empty[BasicBlock, BlockSummary]

  override def build(): FunSummary = {
    type ObjectCache        = Iterable[(String, SymbolicObject)]
    type PropertyWriteCache = Iterable[(String, ObjectSideEffect)]
    type Entry              = (BasicBlock, ObjectCache, PropertyWriteCache)
    val worklist = mutable.Queue.empty[Entry]
    worklist += ((bbCfg.entry, List.empty, List.empty))
    while (worklist.nonEmpty) {
      val (bb, prevObjectCache, prevPropWriteCache) = worklist.dequeue()
      if (!bbToSummary.contains(bb)) {
        val blockSummaryBuilder = new DefaultBlockSummaryBuilder(bb, methodProcessor, depth, maxDepth)
        val blockSummary        = blockSummaryBuilder.build(prevObjectCache, prevPropWriteCache)
        bbToSummary += bb -> blockSummary
        bbCfg
          .getSuccsOf(bb)
          .foreach(succBB => worklist += ((succBB, blockSummary.objectCache, blockSummary.propertyWriteCache)))
      }
    }
    buildFunSummary()
  }

  private def buildFunSummary(): FunSummary = {
    val blockSummaries  = bbToSummary.values
    val sideEffectNames = parameters ++ returnNames
    val returnValues    = blockSummaries.flatMap(_.returnValue)
    val objectCache = {
      val pairs =
        blockSummaries.flatMap(bs => bs.objectCache).filter(pair => sideEffectNames.contains(pair._1))
      MultiDict.from(pairs)
    }
    val propertyWriteCache = {
      val pairs =
        blockSummaries
          .flatMap(bs => bs.propertyWriteCache)
          .filter(pair => sideEffectNames.contains(pair._1))
      MultiDict.from(pairs)
    }
    val parameterSideEffects = {
      val tmp   = objectCache ++ propertyWriteCache
      val pairs = tmp.filter(x => parameters.contains(x._1)).map(x => (parameters.indexOf(x._1), x._2))
      MultiDict.from(pairs)
    }
    FunSummary(
      bbToSummary.toMap,
      parameters,
      returnValues.toSet,
      parameterSideEffects,
      MultiDict.empty,
      objectCache,
      propertyWriteCache
    )
  }
}
