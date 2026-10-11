package bee.zipper.core.vuln

import io.circe.*
import io.circe.generic.auto.*
import io.circe.syntax.*

/** A method sanitizer can be identified either by the concrete receiver expression (e.g.
  * <code>$this-&gt;security</code>) or by the static type name of the receiver. In many real-world code bases the
  * receiver expression is not available in the <code>code</code> field of the {@link Call#receiver} – for example when
  * the method is invoked on an object returned by another call (<code>foo()-&gt;bar()</code>). Therefore we
  * additionally allow an optional <code>typeName</code> so that sanitizers can be configured in a way similar to the
  * sink specifications.
  *
  * Both <code>receiverName</code> and <code>typeName</code> are optional. When both are provided, **either** of them
  * matching is considered a hit because we only need one proof that the call is to a sanitizer. The default value is
  * <code>None</code> so that existing JSON configurations that only specify <code>receiverName</code> (or none of them)
  * continue to work without any modification.
  */
case class MethodSanitizer(
  receiverName: Option[String] = None,
  methodName: String,
  typeName: Option[String] = None,
  args: Option[Seq[Int]] = None,
  excludeArgs: Option[Seq[Int]] = None
)

/** A function sanitizer specification. It supports optional argument indexes to indicate which arguments are considered
  * sanitized. When args is None, it means all arguments are considered sanitized (backward compatible with plain string
  * entries in JSON).
  */
case class FunSanitizer(name: String, args: Option[Seq[Int]] = None, excludeArgs: Option[Seq[Int]] = None)

case class VulnSanitizer(
  functions: List[FunSanitizer] = Nil,
  methods: List[MethodSanitizer] = Nil,
  regexes: List[String] = Nil
)

case class LanguageSanitizers(
  typeSanitizer: List[String] = Nil,
  genericSanitizer: List[String] = Nil,
  vulnSanitizer: Map[String, VulnSanitizer] = Map.empty
)

type SanitizerSpec = Map[String, LanguageSanitizers]

object SanitizerSpec {
  // Support decoding function sanitizers from either a plain string (name only)
  // or an object { "name": string, "args": [int, ...] }
  implicit val funSanitizerDecoder: Decoder[FunSanitizer] =
    Decoder.instance { cursor =>
      cursor.as[String].map(name => FunSanitizer(name, None)).orElse {
        for {
          name <- cursor.downField("name").as[String]
          args <- cursor.downField("args").as[Option[Seq[Int]]]
          ex   <- cursor.downField("excludeArgs").as[Option[Seq[Int]]]
        } yield FunSanitizer(name, args, ex)
      }
    }

  def fromJson(json: String): Option[SanitizerSpec] =
    parser.decode[SanitizerSpec](json).toOption

  def toJson(spec: SanitizerSpec): String =
    spec.asJson.spaces2

  def merge(specs: List[SanitizerSpec]): SanitizerSpec = {
    specs
      .flatMap(_.toList) // convert into a flat list of (language, LanguageSanitizers) pairs
      .groupBy(_._1)     // group by language
      .view
      .mapValues { groupedLangSanitizers =>
        val sanitizers = groupedLangSanitizers.map(_._2) // extract all LanguageSanitizers for the same language
        LanguageSanitizers(
          typeSanitizer = sanitizers.flatMap(_.typeSanitizer).distinct,
          genericSanitizer = sanitizers.flatMap(_.genericSanitizer).distinct,
          vulnSanitizer = sanitizers
            .flatMap(_.vulnSanitizer.toSeq) // convert into (vulnerability type, VulnSanitizer) pairs
            .groupBy(_._1)                  // group by vulnerability type
            .view
            .mapValues { groupedVulnSanitizer =>
              val vulnSanitizers = groupedVulnSanitizer.map(_._2)

              def mergeFunSanitizers(funs: List[FunSanitizer]): List[FunSanitizer] = {
                funs
                  .groupBy(_.name)
                  .view
                  .mapValues { sameNameFuns =>
                    val mergedArgs: Option[Seq[Int]] = {
                      val allArgs = sameNameFuns.flatMap(_.args.getOrElse(Seq.empty))
                      if (sameNameFuns.exists(_.args.isEmpty)) None // any None means wildcard (all args)
                      else if (allArgs.isEmpty) Some(Seq.empty)
                      else Some(allArgs.distinct)
                    }
                    val mergedExcludeArgs: Option[Seq[Int]] = {
                      val all = sameNameFuns.flatMap(_.excludeArgs.getOrElse(Seq.empty))
                      if (all.isEmpty) None else Some(all.distinct)
                    }
                    FunSanitizer(sameNameFuns.head.name, mergedArgs, mergedExcludeArgs)
                  }
                  .values
                  .toList
              }

              VulnSanitizer(
                functions = mergeFunSanitizers(vulnSanitizers.flatMap(_.functions)),
                methods = vulnSanitizers.flatMap(_.methods).distinct,
                regexes = vulnSanitizers.flatMap(_.regexes).distinct
              )
            }
            .toMap
        )
      }
      .toMap
  }
}
