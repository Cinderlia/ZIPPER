package bee.zipper.cli.scan

/** subcommand baseclass
  */
trait AppModule extends Runnable {

  /** name of the subcommand
    */
  def name: String

  override def run(): Unit
}
