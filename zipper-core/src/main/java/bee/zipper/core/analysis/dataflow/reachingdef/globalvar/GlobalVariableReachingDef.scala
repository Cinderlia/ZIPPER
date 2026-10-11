package bee.zipper.core.analysis.dataflow.reachingdef.globalvar

import bee.zipper.core.analysis.dataflow.reachingdef.{XReachingDef, XUtils}
import bee.zipper.core.analysis.graph.icfg.*

class GlobalVariableReachingDef(icfg: DefaultICfg, utils: XUtils[String], iterations: Option[Int])
    extends XReachingDef[String](icfg, utils, iterations)
