/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.gateway.handler.root.resources.endpoint.webauthn;

import io.gravitee.am.gateway.handler.common.auth.user.UserAuthenticationManager;
import io.gravitee.am.gateway.handler.common.vertx.utils.UriBuilderRequest;
import io.gravitee.am.gateway.handler.vertx.auth.webauthn.WebAuthn;
import io.gravitee.am.model.Template;
import io.gravitee.am.model.User;
import io.gravitee.am.model.oidc.Client;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.MediaType;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.reactivex.core.http.HttpServerRequest;
import io.vertx.reactivex.ext.web.RoutingContext;
import io.vertx.reactivex.ext.web.Session;
import io.vertx.reactivex.ext.web.templ.thymeleaf.ThymeleafTemplateEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class WebAuthnRegisterEndpoint implements Handler<RoutingContext> {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnRegisterEndpoint.class);
    private static final String CLIENT_CONTEXT_KEY = "client";
    private static final String PARAM_CONTEXT_KEY = "param";
    private UserAuthenticationManager userAuthenticationManager;
    private WebAuthn webAuthn;
    private ThymeleafTemplateEngine engine;

    public WebAuthnRegisterEndpoint(UserAuthenticationManager userAuthenticationManager,
                                    WebAuthn webAuthn,
                                    ThymeleafTemplateEngine engine) {
        this.userAuthenticationManager = userAuthenticationManager;
        this.webAuthn = webAuthn;
        this.engine = engine;
    }

    @Override
    public void handle(RoutingContext routingContext) {
        HttpServerRequest req = routingContext.request();
        switch (req.method()) {
            case GET:
                renderPage(routingContext);
                break;
            case POST:
                createCredentials(routingContext);
                break;
            default:
                routingContext.fail(405);
        }
    }

    private void renderPage(RoutingContext routingContext) {
        try {
            // get client
            final Client client = routingContext.get(CLIENT_CONTEXT_KEY);

            // prepare context
            final String action = UriBuilderRequest.resolveProxyRequest(routingContext.request(), routingContext.request().uri(), null);
            routingContext.put("action", action);

            // render the webauthn register page
            engine.render(routingContext.data(), getTemplateFileName(client), res -> {
                if (res.succeeded()) {
                    routingContext.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML);
                    routingContext.response().end(res.result());
                } else {
                    logger.error("Unable to render WebAuthn register page", res.cause());
                    routingContext.fail(res.cause());
                }
            });
        } catch (Exception ex) {
            logger.error("An error occurs while rendering WebAuthn register page", ex);
            routingContext.fail(503);
        }
    }

    /**
     * The callback route to create registration attestations. Usually this route is <pre>/webauthn/register</pre>
     */
    private void createCredentials(RoutingContext ctx) {
        try {
            // might throw runtime exception if there's no json or is bad formed
            final JsonObject webauthnRegister = ctx.getBodyAsJson();
            final Session session = ctx.session();

            if (isEmptyString(webauthnRegister, "name") || isEmptyString(webauthnRegister, "displayName") || isEmptyString(webauthnRegister, "type")) {
                ctx.fail(400);
            } else {
                // input basic validation is OK

                if (session == null) {
                    logger.warn("No session or session handler is missing.");
                    ctx.fail(500);
                    return;
                }

                // check if user exists in AM
                final Client client = ctx.get(CLIENT_CONTEXT_KEY);
                checkUser(client, webauthnRegister.getString("name"), h -> {
                    if (h.failed()) {
                        ctx.fail(403);
                        return;
                    }
                    // and then create credentials
                    User user = h.result();
                    webauthnRegister.put("id", user.getId());
                    webAuthn.createCredentialsOptions(webauthnRegister, createCredentialsOptions -> {
                        if (createCredentialsOptions.failed()) {
                            ctx.fail(createCredentialsOptions.cause());
                            return;
                        }

                        final JsonObject credentialsOptions = createCredentialsOptions.result();

                        // save challenge to the session
                        ctx.session()
                                .put("challenge", credentialsOptions.getString("challenge"))
                                .put("username", webauthnRegister.getString("name"));

                        ctx.response()
                                .putHeader(io.vertx.core.http.HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8")
                                .end(Json.encodePrettily(credentialsOptions));
                    });
                });
            }
        } catch (IllegalArgumentException e) {
            ctx.fail(400);
        } catch (RuntimeException e) {
            logger.error("Unexpected exception", e);
            ctx.fail(e);
        }
    }

    private void checkUser(Client client, String username, Handler<AsyncResult<User>> handler) {
        userAuthenticationManager.authenticate(client, username)
                .subscribe(
                        user -> handler.handle(Future.succeededFuture(user)),
                        error -> handler.handle(Future.failedFuture(error))
                );
    }

    private String getTemplateFileName(Client client) {
        return Template.WEBAUTHN_REGISTER.template();
    }

    private static boolean isEmptyString(JsonObject json, String key) {
        try {
            if (json == null) {
                return true;
            }
            if (!json.containsKey(key)) {
                return true;
            }
            String s = json.getString(key);
            return s == null || "".equals(s);
        } catch (RuntimeException e) {
            return true;
        }
    }
}
