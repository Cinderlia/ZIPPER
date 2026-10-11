package bee.zipper.util

class Counter(var number: Int = 0) {
  def get(): Int = {
    val res = number
    number += 1
    res
  }

  def clear(): Unit = {
    number = 0
  }
}
