package bee.zipper.core.analysis.taint

import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Computes the data provenance of a control structure condition by walking the dataflow **backwards** from the
  * condition, bounded to a small number of hops and to the enclosing method, and caches the result per control
  * structure.
  *
  * A taint mark (a taint source, a node of an already processed path, or a tainted global/object) stops the walk,
  * because the rest of its path is already recorded in the graph. Reaching a method parameter or a node outside the
  * method also stops the walk: the enhancement never crosses method boundaries.
  */
final class TaintControlFlowProvenance(taintSources: Set[CfgNode]) {
  private val logger = org.slf4j.LoggerFactory.getLogger(this.getClass)

  // the backtrack is limited to 16 hops along REACHING_DEF; if no taint mark is met inside them, the condition is
  // considered unaffected
  private val maxDepth = Integer.getInteger("zipper.controlflow.provenance.depth", 16).intValue()
  private val maxNodes = Integer.getInteger("zipper.controlflow.provenance.nodes", 50000).intValue()

  private case class ControlGraph(
    conditionIds: Set[Long],
    nodes: mutable.Map[Long, CfgNode],
    next: mutable.Map[Long, CfgNode],
    sources: mutable.Set[Long],
    taintHeads: mutable.Set[Long]
  )

  private val graphs       = mutable.Map.empty[Long, ControlGraph]
  private val knownTainted = mutable.Set.empty[Long]
  knownTainted ++= taintSources.map(_.id())

  // cache statistics: graphs are keyed by control-structure id and shared by every path that contains it
  private var lookups: Long      = 0L
  private var misses: Long       = 0L
  private var sampledMisses: Int = 0
  private var lastSampleAt: Long = 0L

  private def graphOf(control: ControlStructure): ControlGraph = {
    lookups += 1
    graphs.get(control.id()) match {
      case Some(graph) => graph
      case None =>
        misses += 1
        val now = System.currentTimeMillis()
        // sample a few misses, spread over time, together with the live cache table
        if (sampledMisses < 20 && (sampledMisses < 3 || now - lastSampleAt > 3000)) {
          sampledMisses += 1
          lastSampleAt = now
          logger.info(
            s"[controlflow] cache miss #$misses ${location(control)} cacheSize=${graphs.size} " +
              s"tainted=${knownTainted.size} knownKeys=${graphs.keys.take(20).mkString(",")}"
          )
        }
        if (lookups % 200 == 0)
          logger.info(
            s"[controlflow] cache lookups=$lookups misses=$misses hitRate=${"%.2f".format((lookups - misses).toDouble / lookups)}"
          )
        val graph = buildGraph(control)
        graphs(control.id()) = graph
        graph
    }
  }

  private def location(control: ControlStructure): String =
    s"${control.file.headOption.map(_.name).getOrElse("?")}:${control.lineNumber.getOrElse(-1)} ${control.code.take(40)}"

  private def buildGraph(control: ControlStructure): ControlGraph = {
    val startedAt      = System.currentTimeMillis()
    val methodId       = control.method.id()
    val conditionNodes = control.condition.ast.collectAll[CfgNode].toList
    val graph = ControlGraph(
      conditionNodes.map(_.id()).toSet,
      mutable.Map.empty,
      mutable.Map.empty,
      mutable.Set.empty,
      mutable.Set.empty
    )
    val visited = mutable.Set.empty[Long]
    val queue   = mutable.Queue.empty[(CfgNode, Int)]
    conditionNodes.foreach(node => queue.enqueue((node, 0)))

    while (queue.nonEmpty && visited.size < maxNodes) {
      if (visited.size > 0 && visited.size % 5000 == 0)
        logger.info(s"[controlflow] backtrack ${location(control)} visited=${visited.size} queue=${queue.size}")
      val (node, depth) = queue.dequeue()
      if (visited.add(node.id())) {
        graph.nodes(node.id()) = node
        if (taintSources.exists(_.id() == node.id())) graph.sources += node.id()
        if (knownTainted.contains(node.id())) {
          // a taint mark: the remaining path is already tainted, no need to look further
          graph.taintHeads += node.id()
        } else if (depth < maxDepth && !node.isInstanceOf[MethodParameterIn] && node.method.id() == methodId) {
          node.in(EdgeTypes.REACHING_DEF).collectAll[CfgNode].foreach { previous =>
            if (!visited.contains(previous.id())) {
              graph.next.getOrElseUpdate(previous.id(), node)
              queue.enqueue((previous, depth + 1))
            }
          }
        }
      }
    }
    logger.info(
      s"[controlflow] backtrack ${location(control)} visited=${visited.size} heads=${graph.taintHeads.size} " +
        s"sources=${graph.sources.size} elapsed=${System.currentTimeMillis() - startedAt}ms"
    )
    graph
  }

  def taintHeads(control: ControlStructure): Set[Long] = {
    val graph = graphOf(control)
    graph.taintHeads.toSet ++ graph.sources
  }

  def conditionDependsOnSources(control: ControlStructure): Boolean = graphOf(control).sources.nonEmpty

  def conditionDependsOnPath(control: ControlStructure, pathNodeIds: Set[Long]): Boolean = {
    val graph = graphOf(control)
    graph.nodes.keySet.exists(pathNodeIds.contains)
  }

  /** Path from a taint head up to the condition (both inclusive). */
  def pathToCondition(control: ControlStructure, headId: Long): Option[List[CfgNode]] = {
    val graph = graphOf(control)
    graph.nodes.get(headId).map { head =>
      val result  = mutable.ListBuffer.empty[CfgNode]
      var current = Option(head)
      var hops    = 0
      while (current.nonEmpty && hops <= maxDepth) {
        val node = current.get
        result += node
        if (graph.conditionIds.contains(node.id())) current = None
        else current = graph.next.get(node.id())
        hops += 1
      }
      result.toList
    }
  }

  /** Compatibility entry point: data path from a source to the control condition. */
  def dataPath(source: CfgNode, control: ControlStructure): Option[List[CfgNode]] =
    pathToCondition(control, source.id())

  def markTainted(nodes: Iterable[CfgNode]): Unit = nodes.foreach(node => knownTainted += node.id())

  /** Adds, for every control structure of the path, the cached provenance of its condition. */
  def enhance(path: TaintPath): TaintPath = {
    if (path.path.isEmpty) return path

    val pathIds   = path.path.map(_.id()).toSet
    val result    = mutable.ArrayBuffer.from(path.path)
    val processed = mutable.Set.empty[Long]

    path.path.collect { case control: ControlStructure => control }.foreach { control =>
      if (processed.add(control.id())) {
        val heads          = taintHeads(control).filterNot(pathIds.contains)
        val insertionIndex = result.indexWhere(_.id() == control.id())
        if (heads.nonEmpty && insertionIndex >= 0) {
          val additions = heads.toList
            .flatMap(head => pathToCondition(control, head))
            .flatten
            .filterNot(node => result.exists(_.id() == node.id()))
          if (additions.nonEmpty) result.insertAll(insertionIndex, additions)
        }
      }
    }

    markTainted(path.path)
    path.copy(path = result.toList)
  }
}
