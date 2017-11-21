package com.hypertino.services.authtoken

import java.util.Base64

import com.hypertino.authtoken.apiref.authtoken._
import com.hypertino.authtoken.apiref.hyperstorage.{ContentDelete, ContentGet, ContentPut, HyperStorageTransaction}
import com.hypertino.binders.value.{Obj, Value}
import com.hypertino.hyperbus.Hyperbus
import com.hypertino.hyperbus.model.{Created, DynamicBody, ErrorBody, Headers, MessagingContext, NotFound, Ok, ResponseBase, Unauthorized}
import com.hypertino.hyperbus.subscribe.Subscribable
import com.hypertino.hyperbus.transport.api.ServiceRegistrator
import com.hypertino.hyperbus.transport.registrators.DummyRegistrator
import com.hypertino.service.config.ConfigLoader
import com.typesafe.config.Config
import monix.eval.Task
import monix.execution.Scheduler
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.time.{Millis, Seconds, Span}
import org.scalatest.{BeforeAndAfterAll, FlatSpec, Matchers}
import scaldi.Module

import scala.collection.mutable
import scala.concurrent.duration._

class AuthTokenServiceSpec extends FlatSpec with Module with BeforeAndAfterAll with ScalaFutures with Matchers with Subscribable {
  override implicit val patienceConfig = PatienceConfig(timeout = scaled(Span(3, Seconds)))
  implicit val scheduler = monix.execution.Scheduler.Implicits.global
  implicit val mcx = MessagingContext.empty
  bind [Config] to ConfigLoader()
  bind [Scheduler] to scheduler
  bind [Hyperbus] to injected[Hyperbus]
  bind [ServiceRegistrator] to DummyRegistrator

  val hyperbus = inject[Hyperbus]
  val handlers = hyperbus.subscribe(this)
  Thread.sleep(500)

  val hyperStorageContent = mutable.Map[String, Value]()

  def onContentPut(implicit request: ContentPut): Task[ResponseBase] = {
    if (hyperStorageContent.put(request.path, request.body.content).isDefined) {
      Task.eval(Ok(HyperStorageTransaction("100500",request.path, 1l)))
    }
    else {
      Task.eval(Created(HyperStorageTransaction("100500",request.path, 1l)))
    }
  }

  def onContentGet(implicit request: ContentGet): Task[ResponseBase] = {
    hyperStorageContent.get(request.path) match {
      case Some(v) ⇒ Task.eval(Ok(DynamicBody(v)))
      case None ⇒ Task.eval(NotFound(ErrorBody("not-found", Some(request.path))))
    }
  }

  def onContentDelete(implicit request: ContentDelete): Task[ResponseBase] = {
    hyperStorageContent.get(request.path)
    Task.eval(Ok(HyperStorageTransaction("100500",request.path, 1l)))
  }
  val service = new AuthTokenService()

  override def afterAll() {
    service.stopService(false, 10.seconds).futureValue
    hyperbus.shutdown(10.seconds).runAsync.futureValue
  }

  "AuthTokenService" should "create token" in {
    val c = hyperbus
      .ask(TokensPost(CreateSessionToken(), Headers(AuthHeader.AUTHORIZATION_RESULT → Obj.from("user_id" → "100500"))))
      .runAsync
      .futureValue

    c.body.userId shouldBe "100500"
  }

  it should "authorize if token matches" in {
    val c = hyperbus
      .ask(TokensPost(CreateSessionToken(), Headers(AuthHeader.AUTHORIZATION_RESULT → Obj.from("user_id" → "100500"))))
      .runAsync
      .futureValue

    c.body.userId shouldBe "100500"

    val credentials = c.body.tokenId + ":" + c.body.tokenKey
    val authHeader = new String(Base64.getEncoder.encode(credentials.getBytes("UTF-8")), "UTF-8")

    val r = hyperbus
      .ask(ValidationsPost(Validation(s"Token $authHeader")))
      .runAsync
      .futureValue

    r shouldBe a[Created[_]]
    r.body.identityKeys shouldBe Obj.from("user_id" → "100500")
    r.body.extra shouldBe Obj.from("token_id" -> c.body.tokenId)
  }

  it should "unathorize if user doesn't exists" in {
    val r = hyperbus
      .ask(ValidationsPost(Validation("Token bWFtbW90aDoxMjM0NQ==")))
      .runAsync
      .failed
      .futureValue

    r shouldBe a[Unauthorized[_]]
    val b = r.asInstanceOf[Unauthorized[ErrorBody]].body
    b.code shouldBe "token-not-found"
  }
}
