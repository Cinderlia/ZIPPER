package bee.zipper.core.analysis.model.ptr

import bee.zipper.api.solver.sym.extend.*
import bee.zipper.core.ir.Var

trait Ptr

case class VarPtr(v: Var)

trait MemPtr extends Ptr

case class ObjFieldPtr(obj: SymbolicObject | DummyObject, field: String) extends MemPtr

case class ArrayIndexPtr(array: SymbolicArray | DummyObject, index: String) extends MemPtr
