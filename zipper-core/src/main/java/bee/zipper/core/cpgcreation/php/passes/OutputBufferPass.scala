package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** PHP renders HTML by capturing output buffers: `ob_start(); ... echo ...; $html = ob_get_clean();`. The value of the
  * captured buffer is not connected to anything the engine can see, so `return $html;` carries no taint even though the
  * buffer contains whatever the code printed.
  *
  * This pass connects the output that lands inside one `ob_start` ... `ob_get_clean` window with the captured value:
  *   - the arguments of `echo`/`print`/`print_r`/`printf`/`var_dump` between the two calls;
  *   - for a resolved `include`/`require` inside the window, the arguments of the output calls of the included file,
  *     one level deep.
  *
  * An include with a computed target is skipped: the included file cannot be named statically, and treating every file
  * as included would mix unrelated output into the buffer.
  */
class OutputBufferPass(cpg: Cpg) extends CpgPass(cpg) {
  import OutputBufferPass.*

  private val logger = LoggerFactory.getLogger(this.getClass)

  override def run(builder: DiffGraphBuilder): Unit = {
    var edges    = 0
    var captures = 0
    var skipped  = 0

    cpg.call.nameExact(StartName).foreach { start =>
      enclosingMethod(start) match {
        case Some(method) =>
          val calls   = method.call.l.toSeq
          val ordered = calls.sortBy(position)
          val startAt = ordered.indexWhere(_.id == start.id)
          val capture = ordered.drop(startAt + 1).find(c => CaptureNames.contains(c.name))
          capture match {
            case Some(buffer) =>
              captures += 1
              producers(ordered.slice(startAt + 1, ordered.indexWhere(_.id == buffer.id))).foreach { value =>
                builder.addEdge(value, buffer, EdgeTypes.REACHING_DEF)
                edges += 1
              }
              ordered.slice(startAt + 1, ordered.indexWhere(_.id == buffer.id)).foreach {
                case include if IncludeNames.contains(include.name) =>
                  includedFile(include).foreach { file =>
                    cpg.method
                      .filenameExact(file)
                      .call
                      .filter(c => OutputNames.contains(c.name))
                      .argument
                      .foreach { value =>
                        builder.addEdge(value, buffer, EdgeTypes.REACHING_DEF)
                        edges += 1
                      }
                  }
                case _ => ()
              }
            case None => skipped += 1
          }
        case None => skipped += 1
      }
    }

    logger.info(s"Bridged $edges output buffer flows in $captures capture windows ($skipped without a capture call)")
  }

  private def producers(calls: Seq[Call]): Seq[CfgNode] =
    calls
      .filter(c => OutputNames.contains(c.name))
      .flatMap(_.argument.l)

  private def includedFile(include: Call): Option[String] =
    include.argumentOption(1).flatMap { argument =>
      val code = argument.code.trim
      val raw = Option(code.stripPrefix("'").stripSuffix("'"))
        .filterNot(_ == code)
        .orElse(Option(code.stripPrefix("\"").stripSuffix("\"")).filterNot(_ == code))
      raw.filter(_.endsWith(".php"))
    }

  private def position(call: Call): (Int, Int) = (call.lineNumber.getOrElse(0), call.order)

  private def enclosingMethod(node: Call): Option[Method] = {
    var current: Option[CfgNode] = Option(node.method)
    var depth                    = 0
    while (depth < 64 && current.exists(!_.isInstanceOf[Method])) {
      current = flatgraph.Accessors
        .getEdgesIn(current.get)
        .iterator
        .collectFirst {
          case e if e.label == EdgeTypes.AST && e.src.isInstanceOf[CfgNode] =>
            e.src.asInstanceOf[CfgNode]
        }
      depth += 1
    }
    current.collect { case m: Method => m }
  }
}

object OutputBufferPass {
  private val StartName    = "ob_start"
  private val CaptureNames = Set("ob_get_clean", "ob_get_contents", "ob_end_clean")
  private val OutputNames  = Set("echo", "print", "print_r", "printf", "vprintf", "var_dump", "exit", "die")
  private val IncludeNames = Set("include", "include_once", "require", "require_once")
}
