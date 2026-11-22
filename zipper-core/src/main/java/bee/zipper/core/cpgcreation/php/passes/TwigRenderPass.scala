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

/** Twig templates are not part of the PHP CPG: `{{ answer|raw }}` in `assets/templates/faq.twig` has no node, so a
  * value printed without escaping is never reported as an XSS sink.
  *
  * This pass bridges the two sides. It reads the templates the project ships, collects the variables each template
  * prints through the `raw` filter, and then, at every place that names a template (`loadTemplate('./faq.twig')` and
  * the two-argument `render('faq.twig', $vars)`), it adds a synthetic `echo` call that receives the PHP expressions
  * assigned to those variables. The PHP frontend expands an array literal into one `$vars['answer'] = $value`
  * assignment per entry, so the rendered expression itself becomes an argument of the sink and the regular taint
  * analysis can reach it from a database read.
  *
  * The pass is inert for projects without Twig templates.
  */
class TwigRenderPass(cpg: Cpg) extends CpgPass(cpg) {
  import TwigRenderPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    val root = projectRoot()
    if (root.isEmpty) return

    val templates = loadTemplates(root)
    if (templates.isEmpty) return

    val values = arrayEntryValues()
    logger.info("Twig render array entries: " + values.size)
    if (values.isEmpty) return

    val anchors = templateAnchors()
    logger.info("Twig render template references: " + anchors.size + " " + anchors.take(5).map(_._2).mkString(","))
    if (anchors.isEmpty) return

    var sinks     = 0
    var edges     = 0
    val truncated = mutable.ArrayBuffer.empty[String]

    anchors.foreach { case (anchor, name) =>
      templates.get(normalize(name)).foreach { template =>
        val (templateName, rawKeys) = template
        val method                  = Option(anchor.method)
        rawKeys.foreach { key =>
          values.get(key).foreach { writers =>
            if (writers.size > maxWritersPerKey && truncated.size < 20) {
              truncated += key + "(" + writers.size + ")"
            }
            val sink = newSink(templateName, key)
            builder.addNode(sink)
            method.foreach { m =>
              builder.addEdge(m, sink, EdgeTypes.CONTAINS)
              m.block.foreach(block => builder.addEdge(block, sink, EdgeTypes.AST))
            }
            builder.addEdge(anchor, sink, EdgeTypes.CFG)
            val bounded = writers.take(maxWritersPerKey)
            bounded.foreach(value => builder.addEdge(value, sink, EdgeTypes.REACHING_DEF))
            bounded.headOption.foreach(value => builder.addEdge(value, sink, EdgeTypes.ARGUMENT))
            sinks += 1
            edges += bounded.size
          }
        }
      }
    }

    logger.info(
      "Bridged " + edges + " values into " + sinks + " Twig sinks over " + templates.size +
        " templates from " + anchors.size + " template references"
    )
    if (truncated.nonEmpty) {
      logger.warn("Template variables with many writers are bridged partially: " + truncated.mkString(", "))
    }
  }

  /** `$twig->loadTemplate('./faq.twig')` names the template that a page script fills with the variables it renders. The
    * two-argument form `render('faq.twig', $vars)` names it directly.
    */
  private def templateAnchors(): List[(Call, String)] = {
    val loads = cpg.call.nameExact("loadTemplate", "load").toList.flatMap { call =>
      templateArgument(call).map(call -> _)
    }
    val renders = cpg.call.nameExact("render").toList.flatMap { call =>
      templateArgument(call).map(call -> _)
    }
    loads ++ renders
  }

  /** The template named by a call: the first string argument that looks like a template file. The receiver of a method
    * call is an argument in the PHP frontend, so the literal is not necessarily the first one.
    */
  private def templateArgument(call: Call): Option[String] =
    call.argument.l.flatMap(stringLiteral).find(_.endsWith(".twig"))

  private def newSink(template: String, key: String): NewCall = {
    val line = templateLines.getOrElse((template, key), 0)
    NewCall()
      .name(sinkName)
      .code("<twig " + template + ":" + line + "> {{ " + key + "|raw }}")
      .lineNumber(line)
      .typeFullName("string")
      .dispatchType("STATIC_DISPATCH")
      .methodFullName(sinkName)
  }

  /** `$vars['key'] = $value` assignments: the PHP frontend expands an array literal into one assignment per entry. */
  private def arrayEntryValues(): Map[String, List[CfgNode]] = {
    val out = mutable.Map.empty[String, mutable.ArrayBuffer[CfgNode]]
    cpg.call.nameExact(Operators.indexAccess).foreach { indexAccess =>
      val args = indexAccess.argument.l
      if (args.sizeIs == 2 && args.head.isInstanceOf[Identifier]) {
        stringLiteral(args(1)).foreach { key =>
          indexAccess.astParent match {
            case assignment: Call
                if assignment.name == Operators.assignment && assignment
                  .argumentOption(1)
                  .exists(_.id == indexAccess.id) =>
              assignment.argumentOption(2).foreach(out.getOrElseUpdate(key, mutable.ArrayBuffer.empty) += _)
            case _ =>
          }
        }
      }
    }
    out.view.mapValues(_.toList).toMap
  }

  private def stringLiteral(node: Expression): Option[String] = node match {
    case literal: Literal =>
      val code = Option(literal.code).map(_.trim).getOrElse("")
      Option(code).filter(c => c.length > 1 && (c.head == '\'' || c.head == '"')).map(_.substring(1, code.length - 1))
    case _ => None
  }

  /** Templates below the project root, mapped to the variables they print through the `raw` filter. */
  private def loadTemplates(root: String): Map[String, (String, List[String])] = {
    val out  = mutable.Map.empty[String, (String, List[String])]
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
          if (keys.nonEmpty) out += normalize(relative) -> (relative -> keys)
        }
    } finally stream.close()
    logger.info("Found " + out.size + " Twig templates with raw output below " + root)
    out.toMap
  }

  private def skipped(path: Path): Boolean =
    path.iterator().asScala.map(_.toString).exists(skippedDirectories.contains)

  private def rawKeys(path: Path, relative: String): List[String] = {
    val text  = new String(Files.readAllBytes(path), StandardCharsets.UTF_8)
    val found = mutable.LinkedHashSet.empty[String]
    text.linesIterator.zipWithIndex.foreach { case (line, index) =>
      rawExpression.findAllMatchIn(line).foreach { matched =>
        identifierPattern.findFirstMatchIn(matched.group(1)).foreach { id =>
          val name = id.group(0)
          if (!templateKeywords.contains(name)) {
            found += name
            templateLines.getOrElseUpdate((relative, name), index + 1)
          }
        }
      }
    }
    found.toList
  }

  private def normalize(name: String): String =
    name.stripPrefix("./").stripSuffix("\"").stripSuffix("'").split("/").lastOption.getOrElse(name)

  private def projectRoot(): String =
    cpg.metaData.root.headOption.map(_.trim).filter(_.nonEmpty).getOrElse("")
}

object TwigRenderPass {

  /** The synthetic sink is an `echo` call so the existing XSS sink specification finds it. */
  private val sinkName = "echo"

  private val maxTemplates       = 5000
  private val maxDepth           = 12
  private val maxWritersPerKey   = 200
  private val skippedDirectories = Set("vendor", "libs", "node_modules", "fonts")

  private val rawExpression: Regex     = """\{\{-?(.*?)-?\}\}""".r
  private val identifierPattern: Regex = """[A-Za-z_][A-Za-z0-9_]*""".r
  private val templateKeywords         = Set("not", "true", "false", "null", "and", "or", "if", "else")
  private val templateLines            = mutable.Map.empty[(String, String), Int]
}
