package bee.zipper.core.analysis.dataflow.ifds

import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Method}

class IFDSSolver[D](problem: IFDSTabulationProblem[D])
    extends heros.solver.IFDSSolver[CfgNode, D, Method, HerosICfg](problem) {}
