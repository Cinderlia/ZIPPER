package bee.zipper.core.analysis.taint

import io.circe.Json
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.collection.mutable

final class ControlStructurePathDebugReport {
  private case class PathEntry(
    id: Int,
    kind: String,
    originalNodes: List[Json],
    segments: mutable.ListBuffer[Json],
    var enhancedNodes: List[Json]
  ) {
    def toJson: Json = Json.obj(
      "pathId" -> Json.fromInt(id),
      "kind" -> Json.fromString(kind),
      "originalPath" -> Json.fromValues(originalNodes),
      "segments" -> Json.fromValues(segments),
      "enhancedPath" -> Json.fromValues(enhancedNodes)
    )
  }

  private val paths = mutable.ListBuffer.empty[PathEntry]
  private val taintSourcesById = mutable.LinkedHashMap.empty[Long, Json]

  def beginPath(path: TaintPath, taintSources: Set[CfgNode]): Int = synchronized {
    taintSources.foreach(source => taintSourcesById.getOrElseUpdate(source.id(), nodeJson(source)))
    val id = paths.size
    paths += PathEntry(
      id,
      path.kind,
      path.path.map(nodeJson),
      mutable.ListBuffer.empty[Json],
      Nil
    )
    id
  }

  def recordSegment(pathId: Int, segment: Json): Unit = synchronized {
    paths.lift(pathId).foreach(_.segments += segment)
  }

  def finishPath(pathId: Int, enhancedPath: List[CfgNode]): Unit = synchronized {
    paths.lift(pathId).foreach(_.enhancedNodes = enhancedPath.map(nodeJson))
  }

  def writeReport(outputDir: String): Unit = {
    Files.createDirectories(Paths.get(outputDir))
    val report = synchronized {
      Json.obj(
        "reportType" -> Json.fromString("control-structure-debug"),
        "taintSources" -> Json.fromValues(taintSourcesById.values),
        "paths" -> Json.fromValues(paths.map(_.toJson))
      )
    }
    Files.writeString(
      Paths.get(outputDir).resolve("control-structure-debug-report.json"),
      report.spaces2,
      StandardCharsets.UTF_8
    )
  }

  def nodeJson(node: CfgNode): Json = Json.obj(
    "id" -> Json.fromLong(node.id()),
    "nodeType" -> Json.fromString(node.getClass.getSimpleName),
    "code" -> Json.fromString(Option(node.code).getOrElse("")),
    "file" -> node.file.headOption.map(file => Json.fromString(file.name)).getOrElse(Json.Null),
    "line" -> node.lineNumber.map(Json.fromInt).getOrElse(Json.Null),
    "method" -> Option(node.method.fullName).map(Json.fromString).getOrElse(Json.Null)
  )
}
