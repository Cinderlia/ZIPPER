package bee.zipper.core.analysis.taint

import io.circe.Json
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.collection.mutable

enum ReachabilityReportMode {
  case Path, Debug

  def includesDebug: Boolean = this == Debug
}

object ReachabilityReportMode {
  def parse(value: String): Option[ReachabilityReportMode] = value.trim.toLowerCase match {
    case ""      => None
    case "path"  => Some(Path)
    case "debug" => Some(Debug)
    case other   => throw new IllegalArgumentException(s"Unsupported reachability report mode: $other (use path or debug)")
  }
}

final class ReachabilityReportCollector(val mode: ReachabilityReportMode) {
  private case class SourceInfo(
    nodeId: Long,
    sourcePath: Option[String],
    line: Option[Int],
    source: Option[String],
    method: Option[String]
  ) {
    def toJson: Json = Json.obj(
      "nodeId" -> Json.fromLong(nodeId),
      "sourcePath" -> sourcePath.map(Json.fromString).getOrElse(Json.Null),
      "line" -> line.map(Json.fromInt).getOrElse(Json.Null),
      "source" -> source.map(Json.fromString).getOrElse(Json.Null),
      "method" -> method.map(Json.fromString).getOrElse(Json.Null)
    )
  }

  private case class PairEntry(
    from: SourceInfo,
    to: SourceInfo,
    sameMethod: Boolean,
    var evaluated: Boolean = false,
    var reachable: Option[Boolean] = None,
    var cacheHit: Boolean = false,
    var guard: Option[String] = None
  ) {
    def toJson(index: Int): Json = Json.obj(
      "pairIndex" -> Json.fromInt(index),
      "from" -> from.toJson,
      "to" -> to.toJson,
      "sameMethod" -> Json.fromBoolean(sameMethod),
      "evaluated" -> Json.fromBoolean(evaluated),
      "reachable" -> reachable.map(Json.fromBoolean).getOrElse(Json.Null),
      "cacheHit" -> Json.fromBoolean(cacheHit),
      "guard" -> guard.map(Json.fromString).getOrElse(Json.Null)
    )
  }

  private case class PathEntry(id: Int, kind: Option[String], nodes: List[SourceInfo], pairs: List[PairEntry]) {
    def toJson: Json = Json.obj(
      "pathId" -> Json.fromInt(id),
      "kind" -> kind.map(Json.fromString).getOrElse(Json.Null),
      "nodes" -> Json.fromValues(nodes.map(_.toJson)),
      "pairs" -> Json.fromValues(pairs.zipWithIndex.map { case (pair, index) => pair.toJson(index) })
    )
  }

  private case class NodeVisit(order: Int, node: SourceInfo, guard: String) {
    def toJson: Json = Json.obj(
      "order" -> Json.fromInt(order),
      "node" -> node.toJson,
      "guard" -> Json.fromString(guard)
    )
  }

  private case class DebugEntry(
    pathId: Int,
    pairIndex: Int,
    from: SourceInfo,
    to: SourceInfo,
    cacheHit: Boolean,
    reachable: Boolean,
    guard: Option[String],
    stopReason: Option[String],
    visits: List[NodeVisit]
  ) {
    def toJson: Json = Json.obj(
      "pathId" -> Json.fromInt(pathId),
      "pairIndex" -> Json.fromInt(pairIndex),
      "from" -> from.toJson,
      "to" -> to.toJson,
      "cacheHit" -> Json.fromBoolean(cacheHit),
      "reachable" -> Json.fromBoolean(reachable),
      "guard" -> guard.map(Json.fromString).getOrElse(Json.Null),
      "stopReason" -> stopReason.map(Json.fromString).getOrElse(Json.Null),
      "visitedNodes" -> Json.fromValues(visits.map(_.toJson))
    )
  }

  private val pathEntries  = mutable.ListBuffer.empty[PathEntry]
  private val debugEntries = mutable.ListBuffer.empty[DebugEntry]

  def includesDebug: Boolean = mode.includesDebug

  def beginPath(path: List[CfgNode], kind: Option[String]): Int = synchronized {
    val id = pathEntries.size
    val nodes = path.map(sourceInfo)
    val pairs = path.zip(path.drop(1)).map { case (from, to) =>
      PairEntry(sourceInfo(from), sourceInfo(to), from.method == to.method)
    }
    pathEntries += PathEntry(id, kind, nodes, pairs)
    id
  }

  def recordPair(
    pathId: Int,
    pairIndex: Int,
    reachable: Boolean,
    cacheHit: Boolean,
    guard: Option[String]
  ): Unit = synchronized {
    pathEntries.lift(pathId).flatMap(_.pairs.lift(pairIndex)).foreach { pair =>
      pair.evaluated = true
      pair.reachable = Some(reachable)
      pair.cacheHit = cacheHit
      pair.guard = guard
    }
  }

  def recordBfs(
    pathId: Int,
    pairIndex: Int,
    visits: List[(CfgNode, String)],
    reachable: Boolean,
    guard: String,
    stopReason: Option[String] = None
  ): Unit = synchronized {
    if (includesDebug) {
      pathEntries.lift(pathId).flatMap(_.pairs.lift(pairIndex)).foreach { pair =>
        debugEntries += DebugEntry(
          pathId = pathId,
          pairIndex = pairIndex,
          from = pair.from,
          to = pair.to,
          cacheHit = false,
          reachable = reachable,
          guard = Some(guard),
          stopReason = stopReason,
          visits = visits.zipWithIndex.map { case ((node, nodeGuard), order) =>
            NodeVisit(order, sourceInfo(node), nodeGuard)
          }
        )
      }
    }
  }

  def recordCacheHit(pathId: Int, pairIndex: Int, reachable: Boolean): Unit = synchronized {
    if (includesDebug) {
      pathEntries.lift(pathId).flatMap(_.pairs.lift(pairIndex)).foreach { pair =>
        debugEntries += DebugEntry(
          pathId = pathId,
          pairIndex = pairIndex,
          from = pair.from,
          to = pair.to,
          cacheHit = true,
          reachable = reachable,
          guard = None,
          stopReason = Some("cached result; cfgGuard was not executed"),
          visits = Nil
        )
      }
    }
  }

  def writeReports(outputDir: String): Unit = {
    Files.createDirectories(Paths.get(outputDir))
    val pathReport = synchronized {
      Json.obj(
        "reportType" -> Json.fromString("reachability-path"),
        "paths" -> Json.fromValues(pathEntries.map(_.toJson))
      )
    }
    writeJson(outputDir, "reachability-path-report.json", pathReport)

    if (includesDebug) {
      val debugReport = synchronized {
        Json.obj(
          "reportType" -> Json.fromString("reachability-debug"),
          "bfsRuns" -> Json.fromValues(debugEntries.map(_.toJson))
        )
      }
      writeJson(outputDir, "reachability-debug-report.json", debugReport)
    }
  }

  private def sourceInfo(node: CfgNode): SourceInfo = SourceInfo(
    nodeId = node.id(),
    sourcePath = node.file.headOption.map(_.name).filter(_.nonEmpty),
    line = node.lineNumber,
    source = Option(node.code).filter(_.nonEmpty),
    method = Option(node.method.fullName).filter(_.nonEmpty)
  )

  private def writeJson(outputDir: String, fileName: String, json: Json): Unit = {
    Files.writeString(
      Paths.get(outputDir).resolve(fileName),
      json.spaces2,
      StandardCharsets.UTF_8
    )
  }
}
