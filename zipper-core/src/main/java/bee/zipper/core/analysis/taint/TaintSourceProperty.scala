package bee.zipper.core.analysis.taint

/** @param requestKey
  *   key of the request parameter, such as "cmd" of `cmd=XXX`
  * @param structure
  *   the structure of the request parameter value
  */
case class TaintSourceProperty(requestKey: String, structure: InputStructure)
