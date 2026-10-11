package bee.zipper.core.analysis.taint.secondorder

import bee.zipper.core.Api
import bee.zipper.core.analysis.model.database.{DatabaseColumn, DatabaseTable}
import bee.zipper.core.analysis.taint.secondorder.splendor.*
import bee.zipper.core.analysis.taint.sourcesink.{DirectNodeSink, TaintSink}
import bee.zipper.core.analysis.taint.{DefaultTaintAnalysis, TaintAnalysis, TaintAnalysisResult, TaintPath}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.vuln.VulnKind
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

class TwoPhaseTaintAnalysis(
  cpg: Cpg,
  dbTriples: List[DbTriple],
  sources: List[CfgNode],
  sinks: Map[String, List[TaintSink]], // kind to sinks
  vsa: ValueSetResult,
  exploitMode: Boolean = true,
  enableReachAnalysis: Boolean = false
)(implicit ctx: Api)
    extends TaintAnalysis {

  // Separate database operations into read and write triples
  private val (dbReadTriples, dbWriteTriples) = {
    val groupedByOperation = dbTriples.groupBy(_.op).withDefaultValue(List.empty)
    (groupedByOperation(DbOp.Read), groupedByOperation(DbOp.Write))
  }

  private type ColumnTaintPathMap = Map[DatabaseColumn, List[TaintPath]]

  override def analyze(): TaintAnalysisResult = {
    if (dbReadTriples.isEmpty || dbWriteTriples.isEmpty)
      return TaintAnalysisResult(Iterator.empty)

    val tableToWriteColumns = dbWriteTriples.flatMap(_.tableToColumn).toMap
    val tableToReadColumns  = dbReadTriples.flatMap(_.tableToColumn).toMap

    val taintPathsResult = mutable.ListBuffer.empty[TaintPath]

    // Phase 1: Find taint paths from source to database write operations
    val tableToWritePaths = findSourceToDbWritePaths(tableToWriteColumns)

    tableToWritePaths.foreach { case (table, writeTaintPathMap) =>
      // Try matching read operations for this table
      tableToReadColumns.get(table) match {
        case Some(columnReadVarMap) =>
          // Phase 2: Find taint paths from database read operations to sink and merge with write taint paths
          val taintPaths = findDbReadToSinkPaths(writeTaintPathMap, columnReadVarMap)
          taintPathsResult ++= taintPaths
        case None =>
      }
    }

    TaintAnalysisResult(taintPathsResult.iterator)
  }

  private def findSourceToDbWritePaths(
    tableToWriteColumns: Map[DatabaseTable, ColumnVariableMap]
  ): Map[DatabaseTable, ColumnTaintPathMap] = {
    val dummyKind = VulnKind.Xss
    tableToWriteColumns.view
      .mapValues(columnVarMap =>
        columnVarMap.view
          .mapValues(dbWriteNodes =>
            val analysis =
              new DefaultTaintAnalysis(
                cpg,
                sources,
                Map(dummyKind -> dbWriteNodes.map(DirectNodeSink.apply)),
                vsa,
                exploitMode,
                enableReachAnalysis
              )
            val result = analysis.analyze()
            result.paths.toList
          )
          .filter(_._2.nonEmpty)
          .toMap
      )
      .filter(_._2.nonEmpty)
      .toMap
  }

  private def findDbReadToSinkPaths(
    writeTaintPathMap: ColumnTaintPathMap,
    readVarMap: ColumnVariableMap
  ): List[TaintPath] = {
    // Identify common columns between write and read operations
    val commonColumns = writeTaintPathMap.keys.toSet.intersect(readVarMap.keys.toSet)
    if (commonColumns.isEmpty) List.empty
    else {
      val dbReadNodes = commonColumns.flatMap(readVarMap).toList
      val analysis    = new DefaultTaintAnalysis(cpg, dbReadNodes, sinks, vsa, exploitMode, enableReachAnalysis)

      val readToSinkPaths = analysis.analyze().paths.toList

      if (readToSinkPaths.isEmpty) List.empty
      else {
        // Map read variable back to their corresponding columns
        val nodeToColumnMap = readVarMap.toList.flatMap { case (column, node) =>
          node.map(node => (node, column))
        }.toMap

        // Merge paths from source-to-write with read-to-sink
        readToSinkPaths.flatMap(readToSinkPath =>
          val dbReadVar           = readToSinkPath.path.head
          val correspondingColumn = nodeToColumnMap(dbReadVar)
          val sourceToWritePaths  = writeTaintPathMap(correspondingColumn)
          mergePaths(sourceToWritePaths, List(readToSinkPath))
        )
      }
    }
  }

  private def mergePaths(firstPaths: List[TaintPath], secondPaths: List[TaintPath]): List[TaintPath] = {
    for {
      firstPath  <- firstPaths
      secondPath <- secondPaths
    } yield TaintPath(secondPath.kind, firstPath.order, firstPath.path ++ secondPath.path)
  }
}
