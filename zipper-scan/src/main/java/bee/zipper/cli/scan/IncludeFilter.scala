package bee.zipper.cli.scan

import org.slf4j.LoggerFactory

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.{FileSystems, Files, Path, Paths}
import scala.jdk.CollectionConverters.*
import scala.util.Using

/** `--include-files`: analyse only the files named in a list file.
  *
  * The CPG frontend has no "include only" switch, but it does honour `ignoredFiles`, so the list is inverted: every
  * regular file under the project root that is not matched by the list becomes an exclusion. That keeps the file walker
  * (and the parser, and every later pass) away from the rest of a big tree such as a WordPress checkout.
  *
  * Line syntax (one entry per line, blank lines and `#` comments ignored). Globs use the standard `glob:` syntax and
  * are matched against the project-relative path:
  *   - `wp-includes/comment.php` exact project-relative path
  *   - `wp-includes/(star).php` one directory level, e.g. all PHP files in wp-includes
  *   - `wp-content/plugins/my-plugin/(star)(star)` whole subtree of one plugin
  *   - `wp-admin/` a trailing slash keeps a whole directory
  *   - `!wp-includes/blocks/(star)(star)` a leading `!` removes matches of an earlier, broader entry
  *
  * In the list file itself `(star)` is a literal asterisk. Negations are applied after the positive entries.
  */
object IncludeFilter {
  private val logger = LoggerFactory.getLogger(this.getClass)

  private def isGlob(entry: String): Boolean =
    entry.exists(c => c == '*' || c == '?' || c == '[' || c == '{')

  /** A `!` prefix turns an entry into an exclusion, applied after the positive match: a broad entry such as
    * `wp-includes/(star)(star)` can be narrowed by `!wp-includes/blocks/(star)(star)`.
    */
  private def isNegated(entry: String): Boolean = entry.startsWith("!")

  private def stripNegation(entry: String): String = if isNegated(entry) then entry.drop(1).trim else entry

  private def readEntries(listFile: String): Seq[String] =
    Using.resource(Files.newBufferedReader(Paths.get(listFile), StandardCharsets.UTF_8)) { reader =>
      reader
        .lines()
        .iterator()
        .asScala
        .map(_.trim)
        .map(line => if line.contains("#") && !line.startsWith("#") then line.takeWhile(_ != '#').trim else line)
        .filter(line => line.nonEmpty && !line.startsWith("#"))
        .map(_.stripPrefix("./"))
        .toSeq
    }

  /** @return absolute paths of the files that must be excluded so that only the listed ones remain. */
  def excludedPaths(root: File, listFile: String): Seq[String] = {
    val rootPath = root.toPath.toAbsolutePath.normalize
    val entries  = readEntries(listFile)
    if (entries.isEmpty) {
      logger.warn(s"--include-files: '$listFile' is empty, analysing the whole project")
      return Seq.empty
    }

    val fs        = FileSystems.getDefault
    val positives = entries.filterNot(isNegated).map(stripNegation)
    val negatives = entries.filter(isNegated).map(stripNegation)

    def matchersOf(items: Seq[String]) = items.filter(isGlob).map(e => fs.getPathMatcher("glob:" + e))
    def exactOf(items: Seq[String])    = items.filterNot(isGlob).filterNot(_.endsWith("/")).toSet
    def dirsOf(items: Seq[String])     = items.filterNot(isGlob).filter(_.endsWith("/")).map(_.stripSuffix("/") + "/")

    val posMatchers = matchersOf(positives)
    val posExact    = exactOf(positives)
    val posDirs     = dirsOf(positives)
    val negMatchers = matchersOf(negatives)
    val negExact    = exactOf(negatives)
    val negDirs     = dirsOf(negatives)

    def matches(relative: String, ex: Set[String], dirs: Seq[String], ms: Seq[java.nio.file.PathMatcher]): Boolean =
      ex.contains(relative) || dirs.exists(relative.startsWith) || ms.exists(_.matches(Paths.get(relative)))

    def included(relative: String): Boolean =
      matches(relative, posExact, posDirs, posMatchers) && !matches(relative, negExact, negDirs, negMatchers)

    var kept     = 0
    var excluded = 0
    val result   = scala.collection.mutable.ArrayBuffer.empty[String]

    val walker = Files.walk(rootPath)
    try {
      walker.iterator().asScala.filter(Files.isRegularFile(_)).foreach { file =>
        val relative = rootPath.relativize(file).toString.replace('\\', '/')
        if included(relative) then kept += 1
        else {
          excluded += 1
          result += file.toAbsolutePath.toString
        }
      }
    } finally walker.close()

    logger.info(s"--include-files: keeping $kept of ${kept + excluded} files, excluding $excluded")
    if (kept == 0) logger.warn(s"--include-files: no file under $rootPath matched '$listFile'")
    result.toSeq
  }
}
