package bee.zipper.core.analysis.taint.secondorder.splendor

import bee.zipper.core.analysis.model.database.*
import bee.zipper.core.ir.CpgNodeExtension.*
import bee.zipper.util.AnyExtension.*
import io.circe.*
import io.circe.syntax.*
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}

enum DbOp {
  case Read, Write
}

type ColumnVariableMap = Map[DatabaseColumn, List[CfgNode]]

case class DbTriple(call: Call, op: DbOp, tableToColumn: Map[DatabaseTable, ColumnVariableMap])

object DbTriple {
  implicit val encoder: Encoder[DbTriple] = (triple: DbTriple) => {
    implicit val opEncoder: Encoder[DbOp] = Encoder.encodeString.contramap(_.toString)
    implicit val opDecoder: Decoder[DbOp] = Decoder.decodeString.emap {
      case "Read"  => Right(DbOp.Read)
      case "Write" => Right(DbOp.Write)
      case other   => Left(s"invalid DbOp value: $other")
    }
    implicit val columnVariableMapEncoder: Encoder[ColumnVariableMap] = Encoder.instance { map =>
      Json.obj(map.map { case (column, cfgNodes) =>
        column.name -> cfgNodes.asJson
      }.toSeq*)
    }
    implicit val tableMapEncoder: Encoder[Map[DatabaseTable, ColumnVariableMap]] =
      (map: Map[DatabaseTable, ColumnVariableMap]) =>
        Json.obj(map.map { case (table, colVarMap) => table.name -> colVarMap.asJson }.toSeq*)

    Json.obj(
      ("call", triple.call.as[CfgNode].asJson),
      ("op", triple.op.asJson),
      ("tableToColumn", triple.tableToColumn.asJson)
    )
  }
}
