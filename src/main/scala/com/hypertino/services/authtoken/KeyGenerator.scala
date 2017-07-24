package com.hypertino.services.authtoken

import java.security.SecureRandom

import com.hypertino.hyperbus.util.IdGeneratorBase

class KeyGenerator(keySize: Int) extends IdGeneratorBase{
  private val random = new SecureRandom()

  def nextKey(): String = {
    val sb = new StringBuilder(30)
    0 to keySize foreach { _ ⇒
      appendInt(sb, random.nextInt())
    }
    sb.toString
  }
}
