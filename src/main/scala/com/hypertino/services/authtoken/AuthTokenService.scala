package com.hypertino.services.authtoken

import java.util.Base64

import com.hypertino.authtoken.apiref.authtoken._
import com.hypertino.authtoken.apiref.hyperstorage.{ContentDelete, ContentGet, ContentPut, HyperStorageHeader}
import com.hypertino.binders.value.{Null, Obj}
import com.hypertino.hyperbus.Hyperbus
import com.hypertino.hyperbus.model.{BadRequest, Created, DynamicBody, EmptyBody, ErrorBody, Headers, NoContent, NotFound, ResponseBase, Unauthorized}
import com.hypertino.hyperbus.subscribe.Subscribable
import com.hypertino.hyperbus.util.IdGenerator
import com.hypertino.service.control.api.Service
import com.typesafe.scalalogging.StrictLogging
import monix.eval.Task
import monix.execution.Scheduler
import scaldi.{Injectable, Injector}

import scala.concurrent.Future
import scala.concurrent.duration.FiniteDuration

class AuthTokenService(implicit val injector: Injector) extends Service with Injectable with Subscribable with StrictLogging {
  private implicit val scheduler = inject[Scheduler]
  private val hyperbus = inject[Hyperbus]
  private final val DEFAULT_TOKEN_LIFETIME = 365 * 24 * 60 * 60
  private final val keyGenerator = new KeyGenerator(6)
  logger.info(s"${getClass.getName} started")

  private val handlers = hyperbus.subscribe(this, logger)

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
            if (token.dynamic.token_key.toString != tokenKey ||
                token.dynamic.valid_until.toLong < System.currentTimeMillis) {
              throw Unauthorized(ErrorBody("token-not-found"))
            } else {
              Created(ValidationResult(
                identityKeys = Obj.from("user_id" → token.dynamic.user_id),
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
    post.headers.get(AuthHeader.AUTHORIZATION_RESULT).map { authorizationResult ⇒
      val userId = authorizationResult.dynamic.user_id.toString
      val tokenId = IdGenerator.create()
      val tokenKey = keyGenerator.nextKey()
      val ttlInSeconds = post.body.timeToLiveSeconds.getOrElse(DEFAULT_TOKEN_LIFETIME)
      val validUntil = ttlInSeconds.toLong * 1000l + System.currentTimeMillis()

      val token = SessionToken(userId,tokenId,tokenKey,validUntil)
      import com.hypertino.binders.value._
      import com.hypertino.hyperbus.serialization.SerializationOptions.default._
      hyperbus
        .ask(ContentPut(getTokenStoragePath(tokenId), DynamicBody(token.toValue), headers=Headers(
          HyperStorageHeader.HYPER_STORAGE_TTL → ttlInSeconds
        )))
        .map { _ ⇒
          Created(token)
        }
    } getOrElse {
      Task.eval(Unauthorized(ErrorBody("unauthorized")))
    }
  }

  def onTokenDelete(implicit delete: TokenDelete): Task[ResponseBase] = {
    delete.headers.get(AuthHeader.AUTHORIZATION_RESULT).map { authorizationResult ⇒
      val userId = authorizationResult.dynamic.user_id
      hyperbus
        .ask(ContentGet(getTokenStoragePath(delete.tokenId)))
        .flatMap { ok ⇒
          val token = ok.body.content
          if (token.dynamic.user_id != userId) {
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
    logger.info(s"${getClass.getName} stopped")
  }
}
