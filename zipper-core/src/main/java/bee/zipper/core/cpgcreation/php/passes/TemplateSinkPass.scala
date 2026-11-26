package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.matching.Regex

/** Sinks that live outside the PHP code: `{{ answer|raw }}` in a Twig template, or `el.innerHTML = data` in a script
  * file that a PHP page feeds with `echo json_encode($rows)`.
  *
  * The pass only adds sink nodes and edges, so it is cheap and never changes existing flows:
  *
  *   1. every Twig template below the project root contributes one `echo` sink per `|raw` output;
  *   1. every script file contributes one `echo` sink per DOM write (`innerHTML`, `.html(`, `.append(`, ...);
  *   1. a call that names a template (`render('faq.twig', [...])`, `loadTemplate('/faq.twig')`) receives those sinks,
  *      and the values of its context argument are connected to them — array entries by key first, and when no key
  *      matches, every context value is connected (a deliberately coarse bridge, bounded below);
  *   1. a `echo json_encode($x)` in a page that loads `page.js` receives the DOM sinks of that file, connected from
  *      `$x`.
  *
  * The bridging is name based, so it reports where a value *can* end up, not that it certainly does; it is opt-in for
  * that reason.
  */
class TemplateSinkPass(cpg: Cpg) extends CpgPass(cpg) {
  import TemplateSinkPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  private val templateSinkLines = mutable.Map.empty[(String, String), Int]
  private val scriptSinkLines   = mutable.Map.empty[(String, String), Int]

  override def run(builder: DiffGraphBuilder): Unit = {
    val root = projectRoot()
    if (root.isEmpty) return

    val templates = loadTemplates(root)
    val scripts   = loadScripts(root)
    if (templates.isEmpty && scripts.isEmpty) return

    var sinks = 0
    var edges = 0

    sinks += bridgeTemplates(builder, templates)
    edges += lastEdges

    val (scriptSinks, scriptEdges) = bridgeScripts(builder, root, scripts)
    sinks += scriptSinks
    edges += scriptEdges

    logger.info(
      "Template sinks: " + sinks + " sinks, " + edges + " value bridges over " + templates.size +
        " Twig templates and " + scripts.size + " script files"
    )
  }

  private var lastEdges = 0

  // ---------------------------------------------------------------- templates

  private def bridgeTemplates(builder: DiffGraphBuilder, templates: Map[String, Template]): Int = {
    if (templates.isEmpty) return 0
    var sinks = 0
    lastEdges = 0

    templateAnchors().foreach { case (anchor, name) =>
      templates.get(normalize(name)).foreach { template =>
        val method = Option(anchor.method)
        val values = contextValues(anchor)
        if (values.nonEmpty) {
          val byKey = values.groupBy(_._1)
          template.rawKeys.take(maxSinksPerTemplate).foreach { case (key, line) =>
            val matched = byKey.getOrElse(key, Nil)
            val bridged =
              if (matched.nonEmpty) matched.map(_._2)
              else values.take(maxValuesPerSink).map(_._2)
            if (bridged.nonEmpty) {
              val sink = newSink(template.path, line, "{{ " + key + "|raw }}")
              builder.addNode(sink)
              method.foreach { m =>
                builder.addEdge(m, sink, EdgeTypes.CONTAINS)
                m.block.foreach(block => builder.addEdge(block, sink, EdgeTypes.AST))
              }
              builder.addEdge(anchor, sink, EdgeTypes.CFG)
              bridged.distinctBy(_.id).foreach(value => builder.addEdge(value, sink, EdgeTypes.REACHING_DEF))
              builder.addEdge(sink, bridged.head, EdgeTypes.ARGUMENT)
              sinks += 1
              lastEdges += bridged.size
            }
          }
        }
      }
    }
    logger.info("Template sinks bridged: " + sinks + " sinks from " + templateAnchors().size + " template references")
    sinks
  }

  /** Calls that name a template file: `render('faq.twig', $vars)`, `loadTemplate('./faq.twig')`, and the named argument
    * form `render(file: '/faq.twig', context: [...])` used by Symfony style controllers.
    */
  private def templateAnchors(): List[(Call, String)] =
    cpg.call
      .filter { call =>
        call.argument.l.exists(node => stringLiteral(node).exists(_.endsWith(".twig")))
      }
      .toList
      .flatMap(call => call.argument.l.flatMap(stringLiteral).find(_.endsWith(".twig")).map(call -> _))

  /** The values a page hands to the template, as `(key, node)` pairs. Keys come from array literal entries and from
    * `$vars['key'] = $value` assignments; values without a key are reported under the empty key so the coarse fallback
    * can still bridge them.
    */
  private def contextValues(anchor: Call): List[(String, CfgNode)] = {
    val arguments = anchor.argument.l.filterNot(node => stringLiteral(node).exists(_.endsWith(".twig")))
    val out       = mutable.ArrayBuffer.empty[(String, CfgNode)]

    arguments.foreach { argument =>
      keyedValues(argument).foreach { case (key, value) => out += (key -> value) }
    }

    if (out.isEmpty) {
      arguments.foreach { argument =>
        argument.ast.take(maxNodesPerArgument).foreach {
          case node: Identifier                                 => out += ("" -> node)
          case node: Call if node.name != Operators.indexAccess => out += ("" -> node)
          case _                                                =>
        }
      }
    }
    out.toList.distinctBy(pair => (pair._1, pair._2.id))
  }

  /** `$vars['key'] = $value` assignments: the PHP frontend expands an array literal into one assignment per entry, so
    * this covers both `['answer' => $x]` and an explicit `$vars['answer'] = $x`.
    */
  private def keyedValues(node: AstNode): List[(String, CfgNode)] =
    node.ast
      .collectAll[Call]
      .filter(_.name == Operators.assignment)
      .flatMap { assignment =>
        val args = assignment.argument.l
        if (args.sizeIs == 2) {
          args.head match {
            case indexAccess: Call if indexAccess.name == Operators.indexAccess =>
              val indexArgs = indexAccess.argument.l
              if (indexArgs.sizeIs == 2) stringLiteral(indexArgs(1)).map(_ -> args(1).asInstanceOf[CfgNode])
              else None
            case _ => None
          }
        } else None
      }
      .toList

  // ------------------------------------------------------------------ scripts

  private def bridgeScripts(
    builder: DiffGraphBuilder,
    root: String,
    scripts: Map[String, List[(String, Int)]]
  ): (Int, Int) = {
    if (scripts.isEmpty) return (0, 0)

    var sinks    = 0
    var edges    = 0
    val fileText = mutable.Map.empty[String, String]

    def textOf(fileName: String): Option[String] =
      fileText.get(fileName).orElse {
        val path = Paths.get(root, fileName)
        if (Files.isRegularFile(path)) {
          val text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8)
          fileText += fileName -> text
          Some(text)
        } else None
      }

    cpg.call.nameExact("echo", "print").foreach { echo =>
      val json = echo.argument.ast.collectAll[Call].find(_.name == "json_encode")
      json.foreach { encoder =>
        val values = encoder.argument.l
          .flatMap { argument =>
            argument.ast.take(maxNodesPerArgument).collect {
              case node: Identifier if !node.name.startsWith("$") || node.name.nonEmpty => node
            }
          }
          .distinctBy(_.id)
          .take(maxValuesPerSink)
        val page = Option(echo.method).map(m => Option(m.filename).getOrElse("")).getOrElse("")
        if (values.nonEmpty && page.nonEmpty) {
          textOf(page).foreach { text =>
            scripts.foreach { case (name, lines) =>
              if (text.contains(name)) {
                val method = Option(echo.method)
                lines.take(maxSinksPerTemplate).foreach { case (sinkText, line) =>
                  val sink = newSink(name, line, sinkText)
                  builder.addNode(sink)
                  method.foreach { m =>
                    builder.addEdge(m, sink, EdgeTypes.CONTAINS)
                    m.block.foreach(block => builder.addEdge(block, sink, EdgeTypes.AST))
                  }
                  builder.addEdge(echo, sink, EdgeTypes.CFG)
                  values.foreach(value => builder.addEdge(value, sink, EdgeTypes.REACHING_DEF))
                  builder.addEdge(sink, values.head, EdgeTypes.ARGUMENT)
                  sinks += 1
                  edges += values.size
                }
              }
            }
          }
        }
      }
    }
    (sinks, edges)
  }

  // ---------------------------------------------------------------- discovery

  private def newSink(file: String, line: Int, code: String): NewCall =
    NewCall()
      .name(sinkName)
      .code("<template " + file + ":" + line + "> " + code)
      .lineNumber(line)
      .typeFullName("string")
      .dispatchType("STATIC_DISPATCH")
      .methodFullName(sinkName)

  private case class Template(path: String, rawKeys: List[(String, Int)])

  private def loadTemplates(root: String): Map[String, Template] = {
    val out  = mutable.Map.empty[String, Template]
    val base = Paths.get(root)
    if (!Files.isDirectory(base)) return Map.empty
    val stream = Files.walk(base, maxDepth)
    try {
      stream
        .iterator()
        .asScala
        .filter(Files.isRegularFile(_))
        .filter(_.getFileName.toString.endsWith(".twig"))
        .filterNot(skipped)
        .take(maxTemplates)
        .foreach { path =>
          val relative = base.relativize(path).toString
          val keys     = rawKeys(path, relative)
          if (keys.nonEmpty) out += normalize(relative) -> Template(relative, keys)
        }
    } finally stream.close()
    logger.info("Template sinks: " + out.size + " Twig templates with raw output below " + root)
    out.toMap
  }

  /** Script files that write data into the DOM, mapped to the sink sites found in them. */
  private def loadScripts(root: String): Map[String, List[(String, Int)]] = {
    val out  = mutable.Map.empty[String, List[(String, Int)]]
    val base = Paths.get(root)
    if (!Files.isDirectory(base)) return Map.empty
    val stream = Files.walk(base, maxDepth)
    try {
      stream
        .iterator()
        .asScala
        .filter(Files.isRegularFile(_))
        .filter(_.getFileName.toString.endsWith(".js"))
        .filterNot(skipped)
        .take(maxTemplates)
        .foreach { path =>
          val relative = base.relativize(path).toString
          val text     = new String(Files.readAllBytes(path), StandardCharsets.UTF_8)
          val sites = text.linesIterator.zipWithIndex
            .flatMap { case (line, index) =>
              scriptSink.findFirstMatchIn(line).map(_ => (line.trim.take(120), index + 1))
            }
            .take(maxScriptSites)
            .toList
          if (sites.nonEmpty) out += path.getFileName.toString -> sites
        }
    } finally stream.close()
    logger.info("Template sinks: " + out.size + " script files with DOM writes below " + root)
    out.toMap
  }

  private def rawKeys(path: Path, relative: String): List[(String, Int)] = {
    val text  = new String(Files.readAllBytes(path), StandardCharsets.UTF_8)
    val found = mutable.LinkedHashMap.empty[String, Int]
    text.linesIterator.zipWithIndex.foreach { case (line, index) =>
      rawExpression.findAllMatchIn(line).foreach { matched =>
        val expression = matched.group(1)
        if (rawFilter.findFirstIn(expression).nonEmpty) {
          identifierPattern.findFirstMatchIn(expression).foreach { id =>
            val name = id.group(0)
            if (!templateKeywords.contains(name)) {
              found.getOrElseUpdate(name, index + 1)
            }
          }
        }
      }
    }
    found.toList
  }

  private def skipped(path: Path): Boolean =
    path.iterator().asScala.map(_.toString).exists(skippedDirectories.contains)

  private def stringLiteral(node: AstNode): Option[String] = node match {
    case literal: Literal =>
      val code = Option(literal.code).map(_.trim).getOrElse("")
      Option(code).filter(c => c.length > 1 && (c.head == '\'' || c.head == '"')).map(_.substring(1, code.length - 1))
    case _ => None
  }

  private def normalize(name: String): String =
    name.stripPrefix("./").stripSuffix("\"").stripSuffix("'").split("/").lastOption.getOrElse(name)

  private def projectRoot(): String =
    cpg.metaData.root.headOption.map(_.trim).filter(_.nonEmpty).getOrElse("")
}

object TemplateSinkPass {

  private val sinkName = "echo"

  private val maxTemplates        = 5000
  private val maxDepth            = 12
  private val maxSinksPerTemplate = 40
  private val maxValuesPerSink    = 40
  private val maxNodesPerArgument = 200
  private val maxScriptSites      = 200
  private val skippedDirectories  = Set("vendor", "libs", "node_modules", "fonts", "dist", "build")

  private val rawExpression: Regex     = """\{\{-?(.*?)-?\}\}""".r
  private val rawFilter: Regex         = """\|\s*raw\b""".r
  private val identifierPattern: Regex = """[A-Za-z_][A-Za-z0-9_]*""".r
  private val templateKeywords         = Set("not", "true", "false", "null", "and", "or", "if", "else")

  private val scriptSink: Regex =
    """(innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\.html\s*\(|\.append\s*\(|\.after\s*\(|\.before\s*\()""".r
}
