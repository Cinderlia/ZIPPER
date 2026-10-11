package bee.zipper.core.analysis.taint

/** represented the structure of the request parameter value
  */
trait InputStructure

/** represented the key of a map-like structure
  */
trait MapLikeKey extends InputStructure

/** represented the value of a map-like structure
  */
trait MapLikeValue extends InputStructure {

  /** the corresponding key of the value in map-like structure. `None` if any key is ok.
    */
  def key: Option[String]

  def child: Option[InputStructure]
}

/** No structure, just a normal string
  */
case class GeneralString() extends InputStructure

case class HttpArrayKey() extends MapLikeKey

case class HttpArrayValue(key: Option[String], child: Option[InputStructure]) extends MapLikeValue

case class JsonObjectKey() extends MapLikeKey

case class JsonObjectValue(key: Option[String], child: Option[InputStructure]) extends MapLikeValue

object InputStructure {
  def instance(input: InputStructure, poc: String): String = {
    def dfs(structure: InputStructure): String = {
      structure match {
        case _: GeneralString => poc
        case _: HttpArrayKey  => s"[$poc]=value"
        case mv: HttpArrayValue =>
          val nest = mv.child match {
            case Some(child) => dfs(child)
            case None        => poc
          }
          val key = mv.key.getOrElse("")
          s"[$key]=$nest"
        case _: JsonObjectKey => s"{\"$poc\": 0}"
        case mv: JsonObjectValue =>
          val nest = mv.child match {
            case Some(child) => dfs(child)
            case None        => poc
          }
          val key = mv.key.getOrElse("\"key\"")
          s"{$key: \"$poc\"}"
      }
    }
    dfs(input)
  }
}
