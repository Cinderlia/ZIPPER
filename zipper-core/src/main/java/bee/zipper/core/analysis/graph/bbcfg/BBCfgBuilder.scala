package bee.zipper.core.analysis.graph.bbcfg

import bee.zipper.core.analysis.graph.cfg.Cfg

trait BBCfgBuilder {
  def cfg: Cfg

  def build(): BBCfg
}
