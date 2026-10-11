package bee.zipper.core.analysis.graph.vfg

import bee.zipper.core.ir.{ArrayAccess, InstanceFieldAccess, Var}

trait VfgLabel

case class VarLabel(use: Var) extends VfgLabel

trait MemVarLabel[MemVar] extends VfgLabel {
  def uses: List[MemVar]
}

// simple mem variable that doesn't consider pointer analysis

type SimpleMemVar = InstanceFieldAccess | ArrayAccess

case class SimpleMemVarLabel(uses: List[SimpleMemVar]) extends MemVarLabel[SimpleMemVar]

// precise mem variable that represented by pointer

// type PreciseMemVar
