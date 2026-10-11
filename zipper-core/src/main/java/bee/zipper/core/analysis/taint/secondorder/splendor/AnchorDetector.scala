package bee.zipper.core.analysis.taint.secondorder.splendor

import bee.zipper.core.analysis.taint.sourcesink.*
import io.joern.php2cpg.astcreation.PhpBuiltins
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import java.util.Collections.newSetFromMap
import java.util.concurrent.ConcurrentHashMap
import scala.collection.mutable
import scala.collection.parallel.CollectionConverters.*
import scala.jdk.CollectionConverters.*
import scala.util.control.Breaks.*

class AnchorDetector(cpg: Cpg, sources: List[CfgNode], sinks: List[TaintSink], topN: Int = 3) {
  private val blacklist = {
    val allSinks = sinks.map {
      case CallArgumentSink(call, _) => call
      case DirectNodeSink(node)      => node
    }
    val part1 = (sources ++ allSinks).collectAll[Call].map(_.name)
    val part2 = List("$this", "self")
    (part1 ++ part2).toSet
  }

  def detect(): List[String] = {
    val candidates = findCandidates
    val counter    = candidates.groupBy(identity).view.mapValues(_.size).toMap
    val sorted     = counter.toSeq.sortBy(_._2).map(_._1)

    val uniques = mutable.Set.empty[String]
    val result  = mutable.ListBuffer.empty[String]
    breakable {
      sorted
        .map(code =>
          val (obj, funName) = parseFunCode(code)
          if (obj != "") obj else funName
        )
        .foreach(anchor =>
          if (!uniques.contains(anchor) && !blacklist.contains(anchor)) {
            uniques += anchor
            result += anchor
          }
          if (result.size >= topN)
            break
        )
    }
    result.toList
  }

  private def parseFunCode(funcName: String): (String, String) = {
    // "$this->m1->m2->foo" => ("$this->m1->m2", "foo")
    val delimiters = List("::", "->")
    val length     = 2

    val indexOption = delimiters
      .map(funcName.lastIndexOf)
      .filter(_ != -1)
      .maxOption

    indexOption match {
      case Some(index) =>
        val prefix       = funcName.substring(0, index)
        val functionName = funcName.substring(index + length)
        (prefix, functionName)
      case None => ("", funcName)
    }
  }

  private def findCandidates: List[String] = {
    val allSinks = sinks.flatMap {
      case CallArgumentSink(call, arguments) => arguments
      case DirectNodeSink(node)              => List(node)
    }
    val calls = bfs(sources) ++ bfs(allSinks, forward = false)
    val filtered = calls
      .filterNot(call => PhpBuiltins.FuncNames.contains(call.name))
      .filterNot(_.name.contains("<operator"))
    filtered.map(call =>
      val code  = call.code
      val index = code.indexOf('(')
      if (index != -1) code.substring(0, index)
      else code
    )
  }

  private def bfs(starts: List[CfgNode], forward: Boolean = true, maxDepth: Int = 5): List[Call] = {
    val inCalls = newSetFromMap(new ConcurrentHashMap[Call, java.lang.Boolean])
    val visited = newSetFromMap(new ConcurrentHashMap[CfgNode, java.lang.Boolean])

    def impl(start: CfgNode): Unit = {
      val worklist = mutable.Queue.empty[(CfgNode, Int)]
      worklist += ((start, 1))
      while (worklist.nonEmpty) {
        val (node, depth) = worklist.dequeue()
        if (!visited.contains(node)) {
          visited.add(node)
          val (inCall, nextNodes) =
            if (forward)
              DdgUtils.ddgOut(node, depth, maxDepth)
            else
              DdgUtils.ddgIn(node, depth, maxDepth)
          inCalls.addAll(inCall.asJava)
          worklist ++= nextNodes
        }
      }
    }

    starts.par.foreach(impl)
    (visited.asScala.collectAll[Call] ++ inCalls.asScala).distinct.toList
  }
}
