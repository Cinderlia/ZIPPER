package bee.zipper.cli.scan

import picocli.CommandLine
import picocli.CommandLine.{Command, HelpCommand}

import scala.jdk.CollectionConverters.*

object ZipperScanMain {
  @Command(
    name = "ZIPPER",
    subcommands = Array(classOf[HelpCommand]),
    mixinStandardHelpOptions = true,
    version = Array("2025-5")
  )
  private class MainModule

  @main
  def main(args: String*): Unit = {
    val modules = findAppModules("bee.zipper.cli.scan.cmd")
    val cmd     = new CommandLine(new MainModule)
    modules.foreach(module => cmd.addSubcommand(module.name, module))
    cmd.execute(args*)
  }

  private def findAppModules(path: String): Seq[AppModule] = {
    import org.reflections.Reflections

    import java.lang.reflect.Modifier

    val reflections = new Reflections(path)
    val subTypes    = reflections.getSubTypesOf(classOf[AppModule]).asScala
    subTypes.flatMap { cls =>
      try {
        if (!Modifier.isAbstract(cls.getModifiers))
          Some(cls.getDeclaredConstructor().newInstance())
        else
          None
      } catch {
        case e: Exception => None
      }
    }.toSeq
  }
}
