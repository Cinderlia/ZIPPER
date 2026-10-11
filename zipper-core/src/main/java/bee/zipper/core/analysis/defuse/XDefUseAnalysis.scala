package bee.zipper.core.analysis.defuse

import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XUtils}
import bee.zipper.core.analysis.graph.icfg.DefaultICfg

trait XDefUseAnalysis[V, DefUse <: XDefUse[V]](icfg: DefaultICfg) {
  protected val utils: XUtils[V]

  protected val reachingDefResult: ReachingDefResult

  protected val defUse: DefUse

  def solve(): DefUse = {
    import defUse.{defines, useToVar, uses}

    icfg.getNodes.foreach(stmt =>
      val reachingDefs = reachingDefResult.getReachingDefs(stmt)
      val useVars      = utils.getUsesOf(stmt)
      useVars.foreach(useVar =>
        reachingDefs
          .foreach(reachingDef =>
            val defVars = utils.getDefVarsOf(reachingDef)
            defVars.foreach(defVar =>
              if (defVar == useVar) {
                uses += reachingDef             -> stmt
                useToVar += (reachingDef, stmt) -> useVar
                defines += (stmt, useVar)       -> reachingDef
              }
            )
          )
      )
    )

    defUse
  }
}
