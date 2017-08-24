package com.hypertino.services.authtoken

import java.security.SecureRandom
import java.util.Base64

import com.hypertino.authtoken.apiref.authtoken._
import com.hypertino.authtoken.apiref.hyperstorage.{ContentDelete, ContentGet, ContentPut}
import com.hypertino.binders.value.{Null, Obj}
import com.hypertino.hyperbus.Hyperbus
import com.hypertino.hyperbus.model.{BadRequest, Created, DynamicBody, EmptyBody, ErrorBody, NoContent, NotFound, Ok, ResponseBase, Unauthorized}
import com.hypertino.hyperbus.util.IdGenerator
import com.hypertino.service.control.api.Service
import monix.eval.Task
import monix.execution.Scheduler
import org.slf4j.LoggerFactory
import scaldi.{Injectable, Injector}

import scala.concurrent.Future
import scala.concurrent.duration.FiniteDuration

class AuthTokenService(implicit val injector: Injector) extends Service with Injectable {
  private implicit val scheduler = inject[Scheduler]
  private val hyperbus = inject[Hyperbus]
  private val log = LoggerFactory.getLogger(getClass)
  private final val DEFAULT_TOKEN_LIFETIME = 365 * 24 * 60 * 60
  private final val keyGenerator = new KeyGenerator(6)
  log.info("AuthTokenService started")

  private val handlers = hyperbus.subscribe(this, log)

  def onValidationsPost(implicit post: ValidationsPost): Task[ResponseBase] = {
    val authorization = post.body.authorization
    val spaceIndex = authorization.indexOf(" ")
    if (spaceIndex < 0 || authorization.substring(0, spaceIndex).compareToIgnoreCase("token") != 0) {
      Task.eval(BadRequest(ErrorBody("format-error")))
    }
    else {
      val base64 = authorization.substring(spaceIndex + 1)
      val tokenIdAndKey = new String(Base64.getDecoder.decode(base64), "UTF-8")
      val semicolonIndex = tokenIdAndKey.indexOf(":")
      if (semicolonIndex < 0) {
        Task.eval(BadRequest(ErrorBody("format-error-token-id")))
      }
      else {
        val tokenId = tokenIdAndKey.substring(0, semicolonIndex)
        val tokenKey = tokenIdAndKey.substring(semicolonIndex + 1)
        hyperbus
          .ask(ContentGet(getTokenStoragePath(tokenId)))
          .map { ok ⇒
            val token = ok.body.content
            if (token.token_key.toString != tokenKey ||
                token.valid_until.toLong < System.currentTimeMillis) {
              throw Unauthorized(ErrorBody("token-not-found"))
            } else {
              Created(ValidationResult(
                identityKeys = Obj.from("user_id" → token.user_id),
                extra = Null
              ))
            }
          }
          .onErrorRecover {
            case _: NotFound[_] ⇒
              Unauthorized(ErrorBody("token-not-found"))
          }
      }
    }
  }

  def onTokensPost(implicit post: TokensPost): Task[ResponseBase] = {
    post.headers.get("Authorization-Result").map { authorizationResult ⇒
      val userId = authorizationResult.user_id.toString
      val tokenId = IdGenerator.create()
      val tokenKey = keyGenerator.nextKey()
      val validUntil = post.body.timeToLiveSeconds.getOrElse(DEFAULT_TOKEN_LIFETIME).toLong * 1000l +
        System.currentTimeMillis()

      val token = SessionToken(userId,tokenId,tokenKey,validUntil)
      import com.hypertino.binders.value._
      import com.hypertino.hyperbus.serialization.SerializationOptions.default._
      hyperbus
        .ask(ContentPut(getTokenStoragePath(tokenId), DynamicBody(token.toValue)))
        .map { _ ⇒
          Created(token)
        }
    } getOrElse {
      Task.eval(Unauthorized(ErrorBody("unauthorized")))
    }
  }

  def onTokenDelete(implicit delete: TokenDelete): Task[ResponseBase] = {
    delete.headers.get("Authorization-Result").map { authorizationResult ⇒
      val userId = authorizationResult.user_id
      hyperbus
        .ask(ContentGet(getTokenStoragePath(delete.tokenId)))
        .flatMap { ok ⇒
          val token = ok.body.content
          if (token.user_id != userId) {
            Task.raiseError[ResponseBase](Unauthorized(ErrorBody("token-not-found")))
          }
          else {
            hyperbus
              .ask(ContentDelete(getTokenStoragePath(delete.tokenId)))
              .map { _ ⇒
                NoContent(EmptyBody)
              }
          }
        }
    } getOrElse {
      Task.eval(Unauthorized(ErrorBody("unauthorized")))
    }
  }

  private def getTokenStoragePath(tokenId: String) = s"auth-token-service/tokens/$tokenId"

  override def stopService(controlBreak: Boolean, timeout: FiniteDuration): Future[Unit] = Future {
    handlers.foreach(_.cancel())
    log.info("AuthTokenService stopped")
  }
}
