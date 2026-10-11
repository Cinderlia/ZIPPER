package bee.zipper.core.analysis.model.database

import bee.zipper.core.analysis.model.database.SchemaAnalysis.*
import net.sf.jsqlparser.parser.CCJSqlParserUtil
import net.sf.jsqlparser.statement.create.table.CreateTable

import java.io.File
import java.sql.{Connection, DriverManager, SQLException}
import scala.compiletime.uninitialized
import scala.io.Source

trait SchemaAnalysis {
  def analyze(): DatabaseSchema
}

object SchemaAnalysis {
  def readSqlFiles(sqlFiles: List[File]): List[String] = {
    sqlFiles.map { file =>
      val source = Source.fromFile(file)
      try {
        source.mkString
      } finally {
        source.close()
      }
    }
  }

  def collectSqlFiles(directory: String): List[File] = {
    val dir = new File(directory)
    if (dir.exists && dir.isDirectory) dir.listFiles().filter(_.getName.endsWith(".sql")).toList
    else List.empty
  }
}

object StaticSqlFileAnalysis {
  def analyze(sqlContents: List[String]): DatabaseSchema = {
    val analysis = new StaticSqlFileAnalysis(sqlContents)
    analysis.analyze()
  }

  def analyzeSqlFiles(sqlFiles: List[File]): DatabaseSchema = {
    val analysis = new StaticSqlFileAnalysis(readSqlFiles(sqlFiles))
    analysis.analyze()
  }
}

/** Generate the database schema by analyze the .sql files of given project
  */
class StaticSqlFileAnalysis(sqlContents: List[String]) extends SchemaAnalysis {
  override def analyze(): DatabaseSchema = {
    val schema = new DatabaseSchema
    sqlContents.foreach(sql =>
      val part = parseSqlToSchema(sql)
      schema.union(part)
    )
    schema
  }

  protected def parseSqlToSchema(sqlContent: String): DatabaseSchema = {
    def cleanName(rawName: String): String = rawName.stripPrefix("`").stripSuffix("`")

    val schema = new DatabaseSchema
    try {
      val parser = CCJSqlParserUtil.parseStatements(sqlContent)
      parser.forEach {
        case createTable: CreateTable =>
          val table   = new DatabaseTable(cleanName(createTable.getTable.getName))
          val columns = createTable.getColumnDefinitions
          if (columns != null) {
            columns.forEach { column =>
              val colName = cleanName(column.getColumnName)
              val colType = column.getColDataType.getDataType
              table.addColumn(DatabaseColumn(colName, colType))
            }
          }
          schema.addTable(table)
        case _ =>
      }
    } catch {
      case ex: Exception => ex.printStackTrace()
    }
    schema
  }
}

class DynSqlFileAnalysis(sqlFiles: List[File]) extends SchemaAnalysis {
  private var connection: Connection = uninitialized
  private val schema                 = new DatabaseSchema

  def this(directory: String) = this(collectSqlFiles(directory))

  override def analyze(): DatabaseSchema = {
    val tempDatabasePath = createTempDatabaseFile()
    connect(tempDatabasePath)
    executeSqlFiles()
    extractSchema()
  }

  private def createTempDatabaseFile(): String = {
    val tempFile = File.createTempFile("tmpSqliteDb", ".db")
    tempFile.deleteOnExit()
    tempFile.getAbsolutePath
  }

  private def connect(database: String): Unit = {
    val url = s"jdbc:sqlite:$database"
    connection = DriverManager.getConnection(url)
  }

  private def executeSqlFiles(): Unit = {
    def splitSqlStatements(sqlContent: String): Seq[String] = {
      sqlContent.split(";").map(_.trim).filter(_.nonEmpty)
    }
    val sqlContents = readSqlFiles(sqlFiles)
    sqlContents.foreach { sql =>
      val statements = splitSqlStatements(sql)
      statements.foreach { statement =>
        val stmt = connection.createStatement()
        try {
          stmt.execute(statement + ";")
        } catch {
          case e: SQLException => println(s"Error executing SQL statement: ${e.getMessage}")
        } finally {
          stmt.close()
        }
      }
    }
  }

  private def extractSchema(): DatabaseSchema = {
    val tablesQuery = "SELECT name FROM sqlite_master WHERE type='table'"
    val statement   = connection.createStatement()
    val tablesRs    = statement.executeQuery(tablesQuery)

    while (tablesRs.next()) {
      val tableName = tablesRs.getString("name")
      val table     = new DatabaseTable(tableName)

      val columnsQuery = s"PRAGMA table_info($tableName)"
      val columnsRs    = statement.executeQuery(columnsQuery)

      while (columnsRs.next()) {
        val columnName = columnsRs.getString("name")
        val columnType = columnsRs.getString("type")
        table.addColumn(DatabaseColumn(columnName, columnType))
      }

      schema.addTable(table)
    }

    statement.close()
    schema
  }
}
