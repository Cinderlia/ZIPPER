package bee.zipper.core.analysis.model.database

import bee.zipper.api.solver.sym.term.StringLiteral
import bee.zipper.core.analysis.vsa.ValueSetResult
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

import java.io.File

class StaticSchemaAnalysis(cpg: Cpg, vsa: ValueSetResult) extends SchemaAnalysis {
  override def analyze(): DatabaseSchema = {
    val schema = new DatabaseSchema
    // step1. parse all sql files in given project
    val sqlFiles = {
      val files = cpg.file.name("\\.sql$")
      files.name.map(path => File(path)).toList
    }
    schema.union(StaticSqlFileAnalysis.analyzeSqlFiles(sqlFiles))
    if (schema.nonEmpty) schema
    else {
      // step2. analyze sql statements in code snippets
      val sqlStatements = collectSqlStatements()
      schema.union(StaticSqlFileAnalysis.analyze(sqlStatements))
      schema
    }
  }

  private def collectSqlStatements(): List[String] = {
    def findFunctionCall(): List[Call] = {
      val functions = Set("dbDelta")
      val regex     = functions.mkString("|")
      cpg.call(regex).filter(_.receiver.isEmpty).toList
    }

    def findMethodCall(): List[Call] = {
      val receivers     = Set(".*db.*", ".*database.*")
      val methods       = Set("query")
      val receiverRegex = receivers.mkString("|")
      val methodRegex   = methods.mkString("|")
      cpg.call(methodRegex).filter(_.receiver.code(receiverRegex).nonEmpty).toList
    }

    val calls = findFunctionCall() ++ findMethodCall()
    val strings = calls.flatMap { call =>
      call.argument
        .filter(_.argumentIndex != 0)
        .flatMap { argument =>
          vsa
            .ptsOf(call, argument, partialEval = true)
            .collect { case StringLiteral(value) => value }
            .map(value => value.replace(".*", ""))
        }
    }
    strings
  }
}
