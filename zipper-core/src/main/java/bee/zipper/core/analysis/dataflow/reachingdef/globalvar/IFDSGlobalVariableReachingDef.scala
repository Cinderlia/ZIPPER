package bee.zipper.core.analysis.dataflow.reachingdef.globalvar

import bee.zipper.core.analysis.dataflow.ifds.HerosICfg
import bee.zipper.core.analysis.dataflow.reachingdef.{IFDSReachingDef, XUtils}

class IFDSGlobalVariableReachingDef(herosICfg: HerosICfg, utils: XUtils[String])
    extends IFDSReachingDef(herosICfg, utils)
