package bee.zipper.util

import bee.zipper.util.sys.FileSys
import org.slf4j.LoggerFactory

import java.io.*
import java.nio.charset.StandardCharsets
import java.nio.file.*
import java.nio.file.attribute.BasicFileAttributes
import java.util.Properties

/** A generic disk-backed cache that tracks source path metadata to determine cache validity.
  *
  * @param baseDir
  *   Cache files that will be put in `cacheDir/baseDir`
  * @param sourcePath
  *   Path to the source file or directory, such as the root folder of a PHP project
  * @param compute
  *   Function to generate the object from [[sourcePath]]
  * @param serialize
  *   Function to serialize the object to string
  * @param deserialize
  *   Function to deserialize the object from string
  */
class DiskCache[T](
  baseDir: String,
  sourcePath: Path,
  compute: Path => T,
  serialize: T => String,
  deserialize: String => Option[T]
) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  private val cacheDir: String = Paths.get("zipper-cache", baseDir).toString
  FileSys.ensureDirectoryExists(cacheDir)
  private val cacheFileName: String = sourcePath.toFile.getName

  private val cacheFile: Path = Paths.get(cacheDir, cacheFileName)
  private val metaFile: Path  = Paths.get(cacheDir, s"$cacheFileName.meta")

  /** Load existing metadata from the .meta file, if present.
    */
  private def loadOldMetadata(): Option[FileMetadata] = {
    if (!Files.exists(metaFile)) return None
    val props = new Properties()
    val in    = new FileInputStream(metaFile.toFile)
    try {
      props.load(in)
      Some(
        FileMetadata(
          props.getProperty("lastModified").toLong,
          props.getProperty("totalSize").toLong,
          props.getProperty("fileCount").toInt
        )
      )
    } finally in.close()
  }

  /** Save metadata to the .meta file.
    */
  private def saveMetadata(meta: FileMetadata): Unit = {
    val props = new Properties()
    props.setProperty("lastModified", meta.lastModified.toString)
    props.setProperty("totalSize", meta.totalSize.toString)
    props.setProperty("fileCount", meta.fileCount.toString)
    val out = new FileOutputStream(metaFile.toFile)
    try props.store(out, null)
    finally out.close()
  }

  /** Get the cached result. If source data has not changed since last caching and cache file exists, returns
    * deserialized result. Otherwise, regenerates and caches a new result.
    */
  def load(): T = {
    val currentMeta = FileMetadata.compute(sourcePath)
    val oldMeta     = loadOldMetadata()
    if (oldMeta.contains(currentMeta) && Files.exists(cacheFile)) {
      logger.info(s"Disk cache hit for $sourcePath, loading from cache: $cacheFile")
      val cacheContent = Files.readString(cacheFile, StandardCharsets.UTF_8)
      deserialize(cacheContent) match {
        case Some(obj) => obj
        case None =>
          logger.warn(s"Failed to deserialize cached object from $cacheFile, recomputing")
          val obj = compute(sourcePath)
          save(obj, updateMeta = true)
          obj
      }
    } else {
      logger.info(s"Disk cache miss for $sourcePath, recomputing and saving to cache: $cacheFile")
      val obj = compute(sourcePath)
      save(obj, updateMeta = true)
      obj
    }
  }

  /** Cache the object manually
    */
  def save(obj: T, updateMeta: Boolean): Unit = {
    val json = serialize(obj)
    Files.write(cacheFile, json.getBytes(StandardCharsets.UTF_8))
    if (updateMeta) {
      val meta = FileMetadata.compute(sourcePath)
      saveMetadata(meta)
    }
  }
}

private case class FileMetadata(lastModified: Long, totalSize: Long, fileCount: Int)

private object FileMetadata {

  /** Compute metadata for the given path (file or directory).
    */
  def compute(path: Path): FileMetadata = {
    if (Files.isDirectory(path)) {
      var lastMod   = 0L
      var totalSize = 0L
      var count     = 0
      Files.walkFileTree(
        path,
        new SimpleFileVisitor[Path]() {
          override def visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult = {
            count += 1
            totalSize += attrs.size()
            lastMod = Math.max(lastMod, attrs.lastModifiedTime().toMillis)
            FileVisitResult.CONTINUE
          }
        }
      )
      FileMetadata(lastMod, totalSize, count)
    } else {
      val attrs = Files.readAttributes(path, classOf[BasicFileAttributes])
      FileMetadata(attrs.lastModifiedTime().toMillis, attrs.size(), 1)
    }
  }
}
