package bee.zipper.core.analysis.dataflow.reachingdef.mem

import bee.zipper.core.analysis.dataflow.ifds.HerosICfg
import bee.zipper.core.analysis.dataflow.reachingdef.{IFDSReachingDef, XUtils}
import bee.zipper.core.analysis.model.ptr.MemPtr

class IFDSMemoryReachingDef(herosICfg: HerosICfg, utils: XUtils[MemPtr]) extends IFDSReachingDef(herosICfg, utils)
