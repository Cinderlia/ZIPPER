package bee.zipper.core.analysis.model.database

enum SqlStmtType {
  case Select, Insert, Update, Delete, Drop, Create
}

case class SqlStmt(queryType: SqlStmtType, table: String, columns: List[String])
