package bee.zipper.core.cpgcreation.x

object RegexEscaper {
  def escape(pattern: String): String = {
    pattern.replace("\\", "\\\\")
  }
}
