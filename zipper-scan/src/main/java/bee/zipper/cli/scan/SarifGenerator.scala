package bee.zipper.cli.scan

import bee.zipper.core.analysis.taint.TaintPath
import bee.zipper.core.vuln.VulnKind
import com.jetbrains.qodana.sarif.SarifUtil
import com.jetbrains.qodana.sarif.model.*
import com.jetbrains.qodana.sarif.model.SarifReport.Version
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

import java.nio.file.Path
import scala.jdk.CollectionConverters.*

object SarifGenerator {
  def forCfgNode(node: CfgNode): Option[Location] = {
    node.file.headOption.map(file =>
      val uri = file.name
      val region = {
        val region = new Region()
        node.lineNumber.foreach(line => region.withStartLine(line))
        node.columnNumber.foreach(column => region.withStartColumn(column))
        region
      }
      val physicalLocation =
        PhysicalLocation()
          .withArtifactLocation(ArtifactLocation().withUri(uri))
          .withRegion(region)
      Location()
        .withMessage(toMessage(node.code))
        .withPhysicalLocation(physicalLocation)
    )
  }

  def forTaintPath(taintPath: TaintPath): Result = {
    def buildCodeFlow(): CodeFlow = {
      val threadFlowLocations =
        taintPath.path.flatMap(forCfgNode).map(location => ThreadFlowLocation().withLocation(location))
      val threadFlow = ThreadFlow().withLocations(threadFlowLocations.asJava)
      val codeFlow   = new CodeFlow()
      codeFlow.setThreadFlows(List(threadFlow).asJava)
      codeFlow
    }

    val kind     = taintPath.kind
    val codeFlow = buildCodeFlow()
    val source   = forCfgNode(taintPath.source)
    val sink     = forCfgNode(taintPath.sink)
    val propertyBag = {
      val bag = new PropertyBag()
      bag.put("kind", kind)
      source.foreach(x => bag.put("source", x))
      sink.foreach(x => bag.put("sink", x))
      bag
    }

    Result()
      .withMessage(toMessage(kind))
      .withRuleId(kind)
      .withLocations(List(sink).flatten.asJava)
      .withCodeFlows(List(codeFlow).asJava)
      .withProperties(propertyBag)
  }

  def reportForTaintPaths(toolName: String, taintPaths: List[TaintPath]): SarifReport = {

    val toolComponent = {
      val rules = VulnKind.values
        .map(kind =>
          val kindName = kind
          ReportingDescriptor().withId(kindName).withName(kindName)
        )
        .asJava
      ToolComponent().withName(toolName).withRules(rules)
    }
    val tool    = Tool().withDriver(toolComponent)
    val results = taintPaths.map(forTaintPath).asJava
    val run     = Run().withTool(tool).withResults(results)
    SarifUtil
      .emptyReport(toolName)
      .withVersion(Version._2_1_0)
      .withRuns(List(run).asJava)
  }

  def writeReport(path: Path, report: SarifReport): Unit = {
    SarifUtil.writeReport(path, report)
  }

  private def toMessage(text: String): Message = Message().withText(text)
}
