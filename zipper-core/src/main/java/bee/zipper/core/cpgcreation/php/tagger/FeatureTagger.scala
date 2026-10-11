package bee.zipper.core.cpgcreation.php.tagger

import bee.zipper.core.cpgcreation.Tagger

enum PhpFeature {
  case DynamicCall, GlobalDataDependency, ObjectDataDependency, WordPressHook, WordPressOption
}

object FeatureTagger extends Tagger[PhpFeature] {
  override val Key: String = "PhpFeatureTag"

  override def serialize(value: PhpFeature): String = value.toString

  override def deserialize(repr: String): PhpFeature = PhpFeature.valueOf(repr)
}
