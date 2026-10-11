package bee.zipper.core

import org.apache.logging.log4j.core.config.Configurator

object Framework {
  def disableJoernLog(): Unit = {
    Configurator.setLevel("io.joern", "OFF")
    Configurator.setLevel("io.shiftleft", "OFF")
    Configurator.setLevel("overflowdb", "OFF")
  }
}
