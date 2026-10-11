package bee.zipper.core.analysis.taint.secondorder.splendor

import bee.zipper.core.analysis.model.database.*
import bee.zipper.core.ir.CpgNodeExtension.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.MemberAccess.isFieldAccess

import scala.collection.mutable
import scala.collection.parallel.CollectionConverters.*

class TripleRecognizer(cpg: Cpg, anchors: List[String], schema: DatabaseSchema, strict: Boolean = false) {
  private val readOperators  = Set("select", "get", "find", "findAll", "fetch", "fetchAll", "read")
  private val writeOperators = Set("insert", "update", "add", "save", "write")

  def recognize(): List[DbTriple] = {
    // step1: find callsites of anchors by string matching
    val calls = anchors.flatMap(anchor =>
      cpg.call
        .filter(_.code.startsWith(anchor))
        .filterNot(call => PhpBuiltins.FuncNames.contains(call.name))
        .filterNot(_.name.contains("<operator"))
    )
    // step2: collect code snippets around anchors
    val infos = calls.par.map(tokenize)
    // step3: try match database triples from code snippets
    infos.flatMap(info => tryMatchTriple(info)).toList
  }

  private class CallInformation(
    val call: Call,
    val tokens: Set[String],
    val memoryStores: Map[Expression, Map[Expression, Expression]]
  ) {
    override def toString: String = {
      val callsite  = call.code
      val tokenShow = "(" + tokens.mkString(", ") + ")"
      val memoryStoreShow = {
        val builder = new StringBuilder()
        memoryStores.foreach { case (arg, pairs) =>
          builder ++= s"Argument: ${arg.code}\n"
          pairs.foreach { (key, value) =>
            builder ++= s"\t${key.code} => ${value.code}\n"
          }
        }
        builder.toString()
      }
      s"$callsite\nTokens: $tokenShow\nMemory Stores:\n$memoryStoreShow"
    }
  }

  private def tryMatchTriple(info: CallInformation): Option[DbTriple] = {
    import info.*

    def matchOperator(): (Boolean, Boolean) = {
      val isRead  = readOperators.intersect(tokens).nonEmpty
      val isWrite = writeOperators.intersect(tokens).nonEmpty
      (isRead, isWrite)
    }

    def matchTable(hasPrefix: Boolean = true): List[DatabaseTable] = {
      val potentialTables = mutable.Set.empty[DatabaseTable]
      schema.getTables.foreach(table =>
        val originTableName = table.name
        var tableName       = originTableName
        if (hasPrefix)
          tableName = tableName.replaceFirst("^.*_", "")
        if (tokens.contains(tableName)) {
          potentialTables += table
        }
      )
      potentialTables.toList
    }

    def matchColumns(op: DbOp, tables: List[DatabaseTable]) = {
      val tableToColumns = mutable.Map.empty[DatabaseTable, ColumnVariableMap]
      tables.foreach(table =>
        val columns = mutable.ListBuffer.empty[DatabaseColumn]
        if (tokens.contains("all_fields")) {
          columns ++= table.getColumns
        } else {
          val matchedColumns =
            table.getColumns.filter(column => tokens.contains(column.name) && column.name != table.name)
          columns ++= matchedColumns
          // handle the database read case `Db::get("channel")` which will read all columns from table `channel`
          if (matchedColumns.isEmpty && op == DbOp.Read) {
            columns ++= table.getColumns
          }
        }
        if (columns.nonEmpty) {
          val pairs = op match {
            case DbOp.Write => matchColumnWriteVariable(columns.toList)
            case DbOp.Read  => matchColumnReadVariable(columns.toList)
          }
          if (pairs.nonEmpty) {
            tableToColumns += table -> pairs
          }
        }
      )
      tableToColumns
    }

    // Helper method to build ColumnVariableMap
    def buildColumnVariableMap(pairs: List[(DatabaseColumn, CfgNode)]): ColumnVariableMap = {
      pairs
        .groupBy(_._1)
        .view
        .mapValues(_.map(_._2))
        .toMap
    }

    def matchColumnWriteVariable(columns: List[DatabaseColumn]): ColumnVariableMap = {
      // Take the below code as an example
      //     $data = array(
      //       'title' => $this->input->get('title'),
      //       'text' => $this->input->get('text'),
      //       'channel_id' => 6,
      //       'image' => $this->input->post('image'),
      //     );
      //     $model->add_data($data);
      // This method is used to record the value-parts of the array, such as `$this->input->get('title')`.
      // The first phase of taint analysis will mark the value-parts as sinks (i.e. find the paths from source to database write site)
      val allMemoryStores = memoryStores.flatMap(_._2)
      val pairs = for {
        column <- columns
        matched = allMemoryStores.filter(_._1.code.contains(column.name))
        value <- matched.values
      } yield column -> value

      buildColumnVariableMap(pairs)
    }

    def matchColumnReadVariable(columns: List[DatabaseColumn]): ColumnVariableMap = {
      // Take the below code as an example
      //     $query = Db::get("channel");
      //     $result = $query->result_array();
      //     echo $result["id"];
      // This method will follow the return value of the database read site (i.e. `Db::get("channel")`)
      // and collect all matched memory-load nodes (i.e. `$result["id"]`)
      val nameToColumn = columns.map(x => x.name -> x).toMap
      val memLoads =
        cpg.call
          .filter(call => isFieldAccess(call.name))
          .flatMap(call =>
            call.argumentOption(2) match {
              case Some(literal: Literal) if literal.isStr =>
                val field = literal.getString
                nameToColumn.get(field).map(column => call -> column)
              case Some(field: FieldIdentifier) =>
                nameToColumn.get(field.code).map(column => call -> column)
              case _ => None
            }
          )
          .toMap
      if (memLoads.isEmpty) Map.empty
      else {
        implicit val context: EngineContext = EngineContext(config = EngineConfig(maxCallDepth = 2, strict = false))
        val paths                           = memLoads.keys.reachableByFlows(info.call)
        val pairs = paths
          .map(path =>
            val memLoad = path.elements.last.asInstanceOf[Call]
            val column  = memLoads(memLoad)
            column -> memLoad
          )
          .toList
        buildColumnVariableMap(pairs)
      }
    }

    val (isRead, isWrite) = matchOperator()
    if (!isRead && !isWrite)
      return None
    val op     = if (isWrite) DbOp.Write else DbOp.Read
    var tables = matchTable()
    if (tables.isEmpty && strict)
      return None
    tables = if (tables.isEmpty) schema.getTables else tables
    val columns = matchColumns(op, tables)
    if (columns.isEmpty)
      return None
    Some(DbTriple(call, op, columns.toMap))
  }

  private def tokenize(call: Call): CallInformation = {
    def splitCode(codes: List[String]): List[String] = {
      val tokens = mutable.Set.empty[String]
      codes.foreach(code =>
        val lower = code.toLowerCase
        tokens += lower
        tokens ++= lower.split('_').filter(_.nonEmpty)
        tokens ++= lower.split('.').filter(_.nonEmpty)
        tokens ++= lower.split(' ').filter(_.nonEmpty)
      )
      tokens.toList
    }

    def splitCallSiteCode(rawCode: String): List[String] = {
      val code = {
        val lower = rawCode.toLowerCase
        val index = rawCode.indexOf('(')
        if (index != -1) lower.substring(0, index) else lower
      }
      val tokens = code.split("->").filter(_.nonEmpty) ++ code.split("::").filter(_.nonEmpty)
      tokens.toList
    }

    def standardize(tokens: List[String]): List[String] = {
      val limitFunctions = "(" + List("count", "max", "min", "date", "date_format", "avg", "length").mkString("|") + ")"
      val regex          = s"$limitFunctions\\(.*?\\)"
      tokens
        .map(token =>
          token
            .replaceAll("\\*", "all_fields")
            .replaceAll(regex, "Integer")
        )
    }

    val callsiteCodes = splitCallSiteCode(call.code)
    val memoryStores  = call.argument.map(arg => arg -> findMemoryStoresOn(arg)).toMap
    val argumentCodes = {
      val nodes = memoryStores.flatMap(x => x._2.keys ++ x._2.values).ast ++ call.argument
      nodes.collect {
        case literal: Literal if literal.isStr => literal.getString
      }.toList
    }
    val codes  = callsiteCodes ++ argumentCodes
    val tokens = standardize(splitCode(codes))
    CallInformation(call, tokens.toSet, memoryStores)
  }

  private def findMemoryStoresOn(start: CfgNode, maxDepth: Int = 2): Map[Expression, Expression] = {
    def ddgIn(entry: (CfgNode, Int)): Iterator[(CfgNode, Int)] = {
      val (node, depth) = entry
      node match {
        case parameter: MethodParameterIn =>
          if (depth > maxDepth) Iterator.empty
          else parameter.argument(NoResolve).map(arg => (arg, depth + 1))
        case _ => node.ddgIn.map(reach => (reach, depth))
      }
    }

    def findArrayStores(block: Block): Map[Expression, Expression] = {
      block.ast.isCall.isAssignment
        .filter(assignment =>
          assignment.target match {
            case target: Call if isFieldAccess(target.name) => true
            case _                                          => false
          }
        )
        .map(assignment => {
          assignment.target -> assignment.source
        })
        .toMap
    }

    def findMemoryStoresBetween(prev: CfgNode, cur: CfgNode): Map[Expression, Expression] = {
      // Take the below code as an example
      //   (1) $user = $other;
      //   (2) $user->name = "x";
      //   (3) $user->save();
      // if [[prev]] is `$user` in line(3) and [[cur]] is `$user` in line(1),
      // this method will collect all memory accesses on `$user` between line(1) and line(3)
      val method         = cur.method
      val highLineOption = prev.lineNumber
      val lowLineOption  = cur.lineNumber
      (highLineOption, lowLineOption) match {
        case (Some(highLine), Some(lowLine)) =>
          val curCode = cur.code
          val memoryAccesses = method.cfgNode.isCall.isAssignment
            .filter(x =>
              val line = x.lineNumber.getOrElse(-1)
              lowLine <= line && line <= highLine
            )
            .filter(assignment =>
              // find assignments like `$user->name = "x"`
              assignment.target match {
                case target: Call
                    if isFieldAccess(target.name) && target.argument.headOption.exists(_.code == curCode) =>
                  true
                case _ => false
              }
            )
            .map(assignment => {
              assignment.target -> assignment.source
            })
            .toMap
          memoryAccesses
        case _ => Map.empty
      }
    }

    case class Entry(prev: Option[CfgNode], cur: CfgNode, depth: Int) {
      def inAssignment: Iterator[Call] = {
        prev match {
          case Some(prev) =>
            // prev is assignment target and cur is assignment source
            prev.inGenericAssignment.filter(assign => assign.source == prev && assign.target == cur)
          case None => Iterator.empty
        }
      }
    }

    val memoryStores = mutable.Map.empty[Expression, Expression]
    val worklist     = mutable.Queue.empty[Entry]
    val visited      = mutable.Set.empty[CfgNode]
    worklist += Entry(None, start, 1)
    while (worklist.nonEmpty) {
      val entry = worklist.dequeue()
      import entry.*
      if (!visited.contains(cur)) {
        visited += cur
        cur match {
          case block: Block =>
            memoryStores ++= findArrayStores(block)
          case _ if prev.isDefined =>
            memoryStores ++= findMemoryStoresBetween(prev.get, cur)
          case _ =>
        }
        if (entry.inAssignment.isEmpty) {
          val ins = ddgIn((cur, depth))
          ins.foreach { case (in, depth) =>
            worklist += Entry(Some(cur), in, depth)
          }
        }
      }
    }
    memoryStores.toMap
  }
}
