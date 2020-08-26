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

import io.gravitee.am.gateway.handler.vertx.auth.webauthn.WebAuthn;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.webauthn.WebAuthnCredentials;
import io.vertx.reactivex.ext.web.RoutingContext;
import io.vertx.reactivex.ext.web.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The callback route to verify attestations and assertions. Usually this route is <pre>/webauthn/response</pre>
 *
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class WebAuthnResponseEndpoint implements Handler<RoutingContext> {
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnResponseEndpoint.class);
    private WebAuthn webAuthn;

    public WebAuthnResponseEndpoint(WebAuthn webAuthn) {
        this.webAuthn = webAuthn;
    }

    @Override
    public void handle(RoutingContext ctx) {
        try {
            // might throw runtime exception if there's no json or is bad formed
            final JsonObject webauthnResp = ctx.getBodyAsJson();
            // input validation
            if (
                    isEmptyString(webauthnResp, "id") ||
                            isEmptyString(webauthnResp, "rawId") ||
                            isEmptyObject(webauthnResp, "response") ||
                            isEmptyString(webauthnResp, "type") ||
                            !"public-key".equals(webauthnResp.getString("type"))) {

                logger.debug("Response missing one or more of id/rawId/response/type fields, or type is not public-key");
                ctx.fail(400);
                return;
            }

            // input basic validation is OK

            final Session session = ctx.session();

            if (ctx.session() == null) {
                logger.error("No session or session handler is missing.");
                ctx.fail(500);
                return;
            }

            webAuthn.authenticate(
                    // authInfo
                    new WebAuthnCredentials()
                            .setChallenge(session.get("challenge"))
                            .setUsername(session.get("username"))
                            .setWebauthn(webauthnResp), authenticate -> {

                        // invalidate the challenge
                        session.remove("challenge");

                        if (authenticate.succeeded()) {
                            final User user = authenticate.result();
                            // save the user into the context
                            ctx.getDelegate().setUser(user);
                            // the user has upgraded from unauthenticated to authenticated
                            // session should be upgraded as recommended by owasp
                            session.regenerateId();
                            ctx.response().end();
                        } else {
                            logger.error("Unexpected exception", authenticate.cause());
                            ctx.fail(authenticate.cause());
                        }
                    });
        } catch (IllegalArgumentException e) {
            logger.error("Unexpected exception", e);
            ctx.fail(400);
        } catch (RuntimeException e) {
            logger.error("Unexpected exception", e);
            ctx.fail(e);
        }
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

    private static boolean isEmptyObject(JsonObject json, String key) {
        try {
            if (json == null) {
                return true;
            }
            if (!json.containsKey(key)) {
                return true;
            }
            JsonObject s = json.getJsonObject(key);
            return s == null;
        } catch (RuntimeException e) {
            return true;
        }
    }
}
