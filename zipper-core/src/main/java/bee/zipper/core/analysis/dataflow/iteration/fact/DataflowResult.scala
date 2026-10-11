package bee.zipper.core.analysis.dataflow.iteration.fact

import bee.zipper.core.analysis.AnalysisResult
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

import scala.collection.mutable

class DataflowResult[Fact] extends AnalysisResult {
  private val inFacts  = mutable.Map.empty[CfgNode, Fact]
  private val outFacts = mutable.Map.empty[CfgNode, Fact]

  def getInFacts: mutable.Map[CfgNode, Fact] = inFacts

  def getOutFacts: mutable.Map[CfgNode, Fact] = outFacts

  def getInFact(node: CfgNode): Fact = inFacts(node)

  def getInFactOption(node: CfgNode): Option[Fact] = inFacts.get(node)

  def setInFact(node: CfgNode, fact: Fact): Unit = inFacts.put(node, fact)

  def getOutFact(node: CfgNode): Fact = outFacts(node)

  def getOutFactOption(node: CfgNode): Option[Fact] = outFacts.get(node)

  def setOutFact(node: CfgNode, fact: Fact): Unit = outFacts.put(node, fact)

  def getOutFactOrElseUpdate(node: CfgNode, fact: Fact): Fact = outFacts.getOrElseUpdate(node, fact)

  def getInFactOrElseUpdate(node: CfgNode, fact: Fact): Fact = inFacts.getOrElseUpdate(node, fact)
}
