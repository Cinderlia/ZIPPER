package bee.zipper.core.analysis.defuse

import bee.zipper.core.analysis.dataflow.reachingdef.{ReachingDefResult, XUtils}
import bee.zipper.core.analysis.graph.icfg.DefaultICfg

trait XDefUseAnalysis[V, DefUse <: XDefUse[V]](icfg: DefaultICfg) {
  protected val utils: XUtils[V]

  protected val reachingDefResult: ReachingDefResult

  protected val defUse: DefUse

  def solve(): DefUse = {
    import defUse.{defines, useToVar, uses}

    // Iterate over the definitions of the used variable and test whether they reach the statement, instead of
    // enumerating every reaching definition of the statement (there can be tens of thousands of them on large
    // programs) and asking which variable each one defines.
    icfg.getNodes.foreach(stmt =>
      val useVars = utils.getUsesOf(stmt)
      useVars.foreach(useVar =>
        utils
          .getDefStmtsOf(useVar)
          .foreach(reachingDef =>
            if (reachingDefResult.reaches(stmt, reachingDef)) {
              uses += reachingDef             -> stmt
              useToVar += (reachingDef, stmt) -> useVar
              defines += (stmt, useVar)       -> reachingDef
            }
          )
      )
    )

    defUse
  }
}
