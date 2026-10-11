package bee.zipper.core.cpgcreation.php.passes

import bee.zipper.api.solver.sym.term.{StringLiteral, SymbolicValue}
import bee.zipper.core.analysis.vsa.ValueSetResult
import bee.zipper.core.cpgcreation.php.tagger.FeatureTagger
import bee.zipper.core.cpgcreation.php.tagger.PhpFeature.WordPressOption
import bee.zipper.core.cpgcreation.x.RegexEscaper
import bee.zipper.core.ir.CpgNodeExtension.*
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.{LayerCreator, LayerCreatorContext}
import org.slf4j.LoggerFactory

import scala.collection.mutable

object WordPressOptionResolutionLayer {
  def run(cpg: Cpg, vsa: ValueSetResult, enhanced: Boolean = true, iterations: Option[Int] = Some(1)): Unit = {
    val context = new LayerCreatorContext(cpg)
    val layer   = new WordPressOptionResolutionLayer(vsa, enhanced, iterations)
    layer.run(context)
  }
}

private class WordPressOptionResolutionLayer(vsa: ValueSetResult, enhanced: Boolean, iterations: Option[Int])
    extends LayerCreator {
  override val overlayName: String = "WordPressOptionResolutionPass"

  override val description: String = "Resolve WordPress option calls (get_option/update_option)"

  override def create(context: LayerCreatorContext): Unit = {
    val cpg  = context.cpg
    val pass = new WordPressOptionResolutionPass(cpg, vsa, enhanced, iterations)
    pass.createAndApply()
  }
}

private enum OptionCallKind {
  case GetOption, UpdateOption, NonOptionCall
}

private object OptionCallKind {
  def getKind(call: Call): OptionCallKind = call match {
    case _ if isGetOption(call)    => GetOption
    case _ if isUpdateOption(call) => UpdateOption
    case _                         => NonOptionCall
  }

  def isGetOption(call: Call): Boolean = {
    call.name == "get_option"
  }

  def isUpdateOption(call: Call): Boolean = {
    call.name == "update_option"
  }
}

class WordPressOptionResolutionPass(cpg: Cpg, vsa: ValueSetResult, enhanced: Boolean, iterations: Option[Int])
    extends CpgPass(cpg) {

  private val logger = LoggerFactory.getLogger(this.getClass)

  /** Registry of option name to value nodes */
  private val optionRegistry = mutable.Map.empty[String, mutable.ListBuffer[CfgNode]]

  override def run(builder: DiffGraphBuilder): Unit = solve()

  private def solve(): Unit = {
    val worklist       = initWorkList()
    var iterationCount = 0

    while (worklist.nonEmpty && (iterations.isEmpty || iterationCount < iterations.get)) {
      logger.info(s"The ${iterationCount + 1}th iteration for resolving WordPress options")
      val builder = Cpg.newDiffGraphBuilder
      val size    = worklist.size

      for (i <- 0 until size) {
        val (call, kind) = worklist.dequeue()
        kind match {
          case OptionCallKind.NonOptionCall =>
          case OptionCallKind.UpdateOption  => forUpdateOption(call, builder)
          case OptionCallKind.GetOption     => forGetOption(call, builder)
        }
      }

      flatgraph.DiffGraphApplier.applyDiff(cpg.graph, builder)
      vsa.clear()
      iterationCount += 1
    }
  }

  private def initWorkList(): mutable.Queue[(Call, OptionCallKind)] = {
    val worklist = mutable.Queue.empty[(Call, OptionCallKind)]
    val kindToCalls =
      cpg.call
        .map(call => (call, OptionCallKind.getKind(call)))
        .groupBy(_._2)
        .withDefaultValue(List.empty)

    import OptionCallKind.*

    val registrationOrder = List(UpdateOption)
    registrationOrder.foreach { kind =>
      worklist ++= kindToCalls(kind)
    }

    val triggerOrder = List(GetOption)
    triggerOrder.foreach { kind =>
      worklist ++= kindToCalls(kind)
    }

    worklist
  }

  private def forUpdateOption(call: Call, builder: DiffGraphBuilder): Unit = {
    logger.info(s"Collect update_option registration ${call.log}")
    // update_option($option, $value, $autoload)
    val optionNameOpt = call.argumentOption(1)
    val valueOpt      = call.argumentOption(2)

    (optionNameOpt, valueOpt) match {
      case (Some(optionNameNode), Some(valueNode)) =>
        val optionNames = vsa
          .ptsOf(call, optionNameNode, partialEval = true)
          .collect { case s: StringLiteral => s.value }

        for (optionName <- optionNames) {
          optionRegistry
            .getOrElseUpdate(optionName, mutable.ListBuffer.empty)
            .addOne(valueNode)
          logger.debug(s"Registered value for option '$optionName'")
        }
        FeatureTagger.bind(builder, call, WordPressOption)

      case _ =>
        logger.warn(s"Invalid update_option call structure: ${call.log}")
    }
  }

  private def forGetOption(call: Call, builder: DiffGraphBuilder): Unit = {
    logger.info(s"Resolve get_option ${call.log}")
    // get_option($option, $default)
    call.argumentOption(1) match {
      case Some(optionNameNode) =>
        val optionNames = vsa
          .ptsOf(call, optionNameNode, partialEval = true)
          .collect { case s: StringLiteral => s.value }

        val allValues = mutable.ListBuffer.empty[CfgNode]

        for (optionName <- optionNames) {
          val directValues = optionRegistry.getOrElse(optionName, mutable.ListBuffer.empty).toList
          allValues ++= directValues

          if (enhanced && directValues.isEmpty && !ValueSetResult.isDotPattern(optionName)) {
            val fuzzyValues = findFuzzyOptionMatches(optionName)
            allValues ++= fuzzyValues
          }
        }

        if (allValues.nonEmpty) {
          // Data flow from values to the call
          allValues.foreach { valueNode =>
            builder.addEdge(valueNode, call, EdgeTypes.REACHING_DEF)
          }
          FeatureTagger.bind(builder, call, WordPressOption)
        } else {
          // If no value is found, data flows from the default value (arg 2) if it exists
          call.argumentOption(2).foreach { defaultNode =>
            builder.addEdge(defaultNode, call, EdgeTypes.REACHING_DEF)
            FeatureTagger.bind(builder, call, WordPressOption)
          }
        }

      case None =>
        logger.warn(s"Invalid get_option call structure: ${call.log}")
    }
  }

  private def findFuzzyOptionMatches(optionNamePattern: String): List[CfgNode] = {
    if (!enhanced || ValueSetResult.isDotPattern(optionNamePattern)) {
      return List.empty
    }

    try {
      val regex         = ("^.*" + RegexEscaper.escape(optionNamePattern) + "$").r
      val matchedValues = mutable.ListBuffer.empty[CfgNode]

      optionRegistry.foreach { case (registeredOption, values) =>
        if (regex.matches(registeredOption)) {
          matchedValues ++= values
        }
      }
      matchedValues.toList
    } catch {
      case e: Exception =>
        logger.warn(s"Fuzzy option pattern <$optionNamePattern> syntax exception")
        List.empty
    }
  }
}
