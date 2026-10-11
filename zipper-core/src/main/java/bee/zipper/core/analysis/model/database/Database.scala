package bee.zipper.core.analysis.model.database

import io.circe.*
import io.circe.generic.semiauto.*
import io.circe.syntax.*

import scala.collection.mutable

case class DatabaseColumn(name: String, datatype: String) {

  /** Determines if the database column is exploitable. It checks if the column's data type is a string and if its
    * length is at least 8.
    */
  def isExploitable: Boolean = {
    def split: (String, Option[Int]) = {
      val typeRegex = """\w+""".r
      val sizeRegex = """\((\d+)""".r
      val dataType  = typeRegex.findFirstIn(datatype).getOrElse("").toLowerCase
      val size      = sizeRegex.findFirstMatchIn(datatype).map(_.group(1).toInt)
      (dataType, size)
    }
    val (raw, precision) = split
    val isString         = DatabaseColumn.stringDataTypes.contains(raw)
    lazy val lengthCheck = if (precision.isDefined) precision.get >= 8 else true
    isString && lengthCheck
  }
}

object DatabaseColumn {
  private lazy val stringDataTypes: Set[String] = Set("char", "varchar", "binary", "varbinary", "blob", "text")

  implicit val decoder: Decoder[DatabaseColumn] = deriveDecoder[DatabaseColumn]
  implicit val encoder: Encoder[DatabaseColumn] = deriveEncoder[DatabaseColumn]
}

class DatabaseTable(val name: String) {
  private val columns = mutable.Map.empty[String, DatabaseColumn]

  def getColumns: List[DatabaseColumn] = columns.values.toList

  def getColumn(name: String): Option[DatabaseColumn] = columns.get(name)

  def apply(name: String): DatabaseColumn = columns(name)

  def addColumn(column: DatabaseColumn): Unit = {
    if (!columns.contains(column.name)) {
      columns += column.name -> column
    }
  }

  def toExploitable: DatabaseTable = {
    val newTable = new DatabaseTable(this.name)
    this.columns.values.filter(_.isExploitable).foreach(newTable.addColumn)
    newTable
  }

  def isEmpty: Boolean = columns.isEmpty

  def nonEmpty: Boolean = columns.nonEmpty

  override def hashCode(): Int = name.hashCode()

  override def equals(obj: Any): Boolean = {
    obj match {
      case other: DatabaseTable => name == other.name
      case _                    => false
    }
  }

  def prettyPrint: String = {
    val tableHeader = s"Table: $name\n"
    val columnRows  = columns.values.map(c => f"${c.name}%-20s | ${c.datatype}").mkString("\n")
    s"$tableHeader$columnRows"
  }

  override def toString: String = name
}

object DatabaseTable {
  implicit val encoder: Encoder[DatabaseTable] = (table: DatabaseTable) =>
    Json.obj(("name", Json.fromString(table.name)), ("columns", table.getColumns.asJson))

  implicit val decoder: Decoder[DatabaseTable] = (c: HCursor) =>
    for {
      name    <- c.downField("name").as[String]
      columns <- c.downField("columns").as[List[DatabaseColumn]]
    } yield {
      val table = new DatabaseTable(name)
      columns.foreach(table.addColumn)
      table
    }
}

class DatabaseSchema {
  private val tables = mutable.Map.empty[String, DatabaseTable]

  def getTables: List[DatabaseTable] = tables.values.toList

  def getTable(name: String): Option[DatabaseTable] = tables.get(name)

  def apply(name: String): DatabaseTable = tables(name)

  def addTable(table: DatabaseTable): Unit = {
    if (!tables.contains(table.name)) {
      tables += table.name -> table
    }
  }

  def union(other: DatabaseSchema): Unit = {
    other.tables.values.foreach(addTable)
  }

  def isEmpty: Boolean = tables.isEmpty

  def nonEmpty: Boolean = tables.nonEmpty

  def toExploitable: DatabaseSchema = {
    val newSchema = new DatabaseSchema
    tables.values.map(_.toExploitable).filter(_.nonEmpty).foreach(newSchema.addTable)
    newSchema
  }

  override def hashCode(): Int = tables.hashCode()

  override def equals(obj: Any): Boolean = {
    obj match {
      case other: DatabaseSchema => tables == other.tables
      case _                     => false
    }
  }

  def prettyPrint: String = {
    val schemaHeader  = "Database Schema:\n"
    val tableSections = tables.values.map(_.prettyPrint).mkString("\n\n")
    s"$schemaHeader$tableSections"
  }

  override def toString: String = s"(${tables.keys.mkString(", ")})"
}

object DatabaseSchema {
  implicit val encoder: Encoder[DatabaseSchema] = (schema: DatabaseSchema) =>
    Json.obj(("tables", schema.getTables.asJson))

  implicit val decoder: Decoder[DatabaseSchema] = (c: HCursor) =>
    for {
      tables <- c.downField("tables").as[List[DatabaseTable]]
    } yield {
      val schema = new DatabaseSchema
      tables.foreach(schema.addTable)
      schema
    }
}
