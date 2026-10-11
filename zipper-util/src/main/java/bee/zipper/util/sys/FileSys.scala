package bee.zipper.util.sys

import java.io.File
import java.nio.file.*
import java.util
import scala.jdk.CollectionConverters.*
import scala.util.matching.Regex

object FileSys {
  val currentDir: File = new File(".")

  def listDir(file: File): List[File] = {
    val all = file.listFiles().toList
    all ++ all.filter(_.isDirectory).flatMap(listDir)
  }

  def findFile(dir: File, name: Regex): Option[File] = {
    findFile(dir, file => name.matches(file.getName))
  }

  def findFile(name: Regex): Option[File] = findFile(currentDir, name)

  def findFile(dir: File, is: File => Boolean): Option[File] = {
    val allFiles = listDir(dir)
    allFiles.find(file => is(file))
  }

  def findFile(is: File => Boolean): Option[File] = findFile(currentDir, is)

  def listResourceDir(dir: String): List[Path] = {
    // https://stackoverflow.com/questions/50469600/how-do-you-list-all-files-in-the-resources-folder-java-scala/67839914
    val loader   = FileSys.getClass.getClassLoader
    val resource = loader.getResource(dir)
    if (resource == null)
      return List.empty
    val uri = resource.toURI
    val path =
      try Paths.get(uri)
      catch {
        // if this is thrown, then it means that we are running the JAR directly (not from an IDE)
        case e: FileSystemNotFoundException =>
          val env = new util.HashMap[String, String]()
          FileSystems.newFileSystem(uri, env).getPath(dir)
      }
    Files.list(path).toList.asScala.toList
  }

  def copyResource(from: String, to: String): Path = {
    val toPath = Paths.get(to)
    if (Files.exists(toPath)) toPath
    else {
      if (toPath.getParent != null) {
        Files.createDirectories(toPath.getParent.toAbsolutePath)
      }
      val loader = FileSys.getClass.getClassLoader
      val in     = loader.getResourceAsStream(from)
      Files.copy(in, toPath)
      toPath
    }
  }

  def copyResource(from: String): Path = copyResource(from, from)

  def ensureDirectoryExists(dir: String): Unit = {
    val dirPath = Paths.get(dir)
    if (!Files.exists(dirPath)) {
      Files.createDirectories(dirPath)
    }
  }
}
