package bee.zipper.core.analysis.dataflow.ifds

import heros.template.DefaultIFDSTabulationProblem
import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}

abstract class IFDSTabulationProblem[D](icfg: HerosICfg)
    extends DefaultIFDSTabulationProblem[CfgNode, D, Method, HerosICfg](icfg)
