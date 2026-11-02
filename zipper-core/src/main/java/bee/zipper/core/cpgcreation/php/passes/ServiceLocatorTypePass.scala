package bee.zipper.core.cpgcreation.php.passes

import io.shiftleft.codepropertygraph.generated.{Cpg, DiffGraphBuilder, EdgeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import scala.collection.mutable

/** Resolves service-locator style object creation such as `$x = $this->getService(Foo::class)` or `$this->foo =
  * $services->get(\A\B\Foo::class)`: the returned object is known to be an instance of the class named by the class
  * literal, so method calls on `$x` (or `$this->foo`) can be linked to `Foo`'s methods.
  *
  * Only method calls whose receiver is directly bound to such an assignment are linked, and only when the target type
  * really declares the method, which keeps the over-approximation small.
  */
class ServiceLocatorTypePass(cpg: Cpg) extends CpgPass(cpg) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  private val ClassLiteral = """^\s*\\?([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*)::class\s*$""".r

  private def serviceType(code: String): Option[String] =
    ClassLiteral.findFirstMatchIn(code).map(_.group(1))

  /** Bindings are scoped either to the enclosing method (for local variables) or to the enclosing type (for
    * `$this->prop`). The key is (scope id, receiver code).
    */
  private def scopeOf(node: CfgNode): Option[Long] = {
    val method = node.method
    if (method == null) None
    else
      Some(
        if (node.code.startsWith("$this->")) method.typeDecl.headOption.map(_.id()).getOrElse(method.id())
        else method.id()
      )
  }

  override def run(builder: DiffGraphBuilder): Unit = {
    val bindings = mutable.HashMap.empty[(Long, String), mutable.Set[String]]
    var sites    = 0

    cpg.call.l.foreach { call =>
      val isLocator =
        call.name == "getService" || (call.name == "get" && call.receiver.l.exists(_.code.contains("services")))
      if (isLocator) {
        val clsOpt = call.argument.l.flatMap(arg => serviceType(arg.code)).headOption
        clsOpt.foreach { cls =>
          call.astParent match {
            case assign: Call if assign.name == "<operator>.assignment" =>
              assign.argument.l.headOption.foreach { lhs =>
                scopeOf(lhs).foreach { scope =>
                  bindings.getOrElseUpdate((scope, lhs.code), mutable.Set.empty) += cls
                  sites += 1
                }
              }
            case _ =>
          }
        }
      }
    }

    if (bindings.isEmpty) {
      logger.info("[service-locator] no service-locator assignment found")
      return
    }

    def parentDecls(typeDecl: TypeDecl): List[TypeDecl] = {
      val parents = typeDecl._inheritsFromOut.collectAll[Type].flatMap(_.referencedTypeDecl).l
      typeDecl :: parents.flatMap(parentDecls)
    }

    val declCache = mutable.HashMap.empty[String, List[TypeDecl]]
    def declsFor(cls: String): List[TypeDecl] = declCache.getOrElseUpdate(
      cls, {
        val short = cls.split("\\\\").last
        val matched = cpg.typeDecl
          .filter(t => t.name == short || t.fullName == cls || t.fullName.endsWith("\\" + cls))
          .l
        matched.flatMap(parentDecls).distinctBy(_.id())
      }
    )

    var candidates = 0
    var linked     = 0
    val linkLog    = mutable.ListBuffer.empty[String]

    cpg.call.l.foreach { call =>
      val isOperator = call.name.startsWith("<operator>")
      if (!isOperator) {
        val receiver = call.receiver.l.headOption.orElse(call.argument.l.headOption)
        receiver.foreach { rcv =>
          scopeOf(rcv).flatMap(scope => bindings.get((scope, rcv.code))).foreach { classes =>
            candidates += 1
            val targets = classes.toList
              .flatMap(declsFor)
              .flatMap(_.method.l)
              .filter(m => m.name.equalsIgnoreCase(call.name))
              .distinctBy(_.id())
            if (targets.nonEmpty) {
              val existing = call.out(EdgeTypes.CALL).collectAll[Method].map(_.id()).toSet
              val toAdd    = targets.filterNot(m => existing.contains(m.id()))
              toAdd.foreach(m => builder.addEdge(call, m, EdgeTypes.CALL))
              if (toAdd.nonEmpty) {
                linked += 1
                if (linkLog.size < 50)
                  linkLog += s"${call.file.name.headOption.getOrElse("?")}:${call.lineNumber.getOrElse(-1)} " +
                    s"${rcv.code}->${call.name} => ${toAdd.map(_.fullName).mkString(",")}"
              }
            }
          }
        }
      }
    }

    logger.info(s"[service-locator] assignments=$sites calls-on-service-receivers=$candidates newly-linked=$linked")
    linkLog.foreach(l => logger.info(s"[service-locator] $l"))
  }
}
