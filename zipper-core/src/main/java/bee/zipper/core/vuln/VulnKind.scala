package bee.zipper.core.vuln

/** Consistent with the design of `Languages` in joern
  */
object VulnKind {
  final val Xss: String              = "Xss"
  final val SqlInjection: String     = "SqlInjection"
  final val CmdInjection: String     = "CmdInjection"
  final val CodeInjection: String    = "CodeInjection"
  final val FileInclusion: String    = "FileInclusion"
  final val FileManipulation: String = "FileManipulation"
  final val ObjectInjection: String  = "ObjectInjection"
  final val Ssrf: String             = "Ssrf"
  final val LogicFlaws: String       = "LogicFlaws"

  final val values: List[String] =
    List(
      Xss,
      SqlInjection,
      CmdInjection,
      CodeInjection,
      FileInclusion,
      FileManipulation,
      ObjectInjection,
      Ssrf,
      LogicFlaws
    )
}
