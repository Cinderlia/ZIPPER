package bee.zipper.core.analysis.dataflow.reachingdef.mem

import bee.zipper.core.analysis.dataflow.reachingdef.{XReachingDef, XUtils}
import bee.zipper.core.analysis.graph.icfg.DefaultICfg
import bee.zipper.core.analysis.model.ptr.MemPtr

class MemoryReachingDef(icfg: DefaultICfg, utils: XUtils[MemPtr], iterations: Option[Int])
    extends XReachingDef[MemPtr](icfg, utils, iterations)
