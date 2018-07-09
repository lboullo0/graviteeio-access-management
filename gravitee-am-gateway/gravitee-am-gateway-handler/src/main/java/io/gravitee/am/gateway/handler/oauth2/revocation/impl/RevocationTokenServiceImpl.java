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
package io.gravitee.am.gateway.handler.oauth2.revocation.impl;

import io.gravitee.am.gateway.handler.oauth2.exception.InvalidGrantException;
import io.gravitee.am.gateway.handler.oauth2.exception.InvalidTokenException;
import io.gravitee.am.gateway.handler.oauth2.revocation.RevocationTokenRequest;
import io.gravitee.am.gateway.handler.oauth2.revocation.RevocationTokenService;
import io.gravitee.am.gateway.handler.oauth2.token.TokenService;
import io.gravitee.am.gateway.handler.oauth2.token.impl.DefaultAccessToken;
import io.gravitee.am.gateway.handler.oauth2.utils.TokenTypeHint;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RevocationTokenServiceImpl implements RevocationTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RevocationTokenServiceImpl.class);

    @Autowired
    private TokenService tokenService;

    @Override
    public Completable revoke(RevocationTokenRequest request) {
        String token = request.getToken();
        String requestingClientId = request.getClientId();

        // Check the refresh_token store first. Fall back to the access token store if we don't
        // find anything. See RFC 7009, Sec 2.1: https://tools.ietf.org/html/rfc7009#section-2.1
        if (request.getHint() != null && request.getHint().equals(TokenTypeHint.REFRESH_TOKEN)) {
            return revokeRefreshToken(token, requestingClientId)
                    .onErrorResumeNext(throwable -> {
                        // if the token was issued to the client making the revocation request
                        // the request is refused and the client is informed of the error
                        if (throwable instanceof InvalidGrantException) {
                            return Completable.error(throwable);
                        }

                        // Note: invalid tokens do not cause an error response since the client
                        // cannot handle such an error in a reasonable way.  Moreover, the
                        // purpose of the revocation request, invalidating the particular token,
                        // is already achieved.
                        // Log the result anyway for posterity.
                        if (throwable instanceof InvalidTokenException) {
                            logger.debug("No refresh token {} found in the token store.", token);
                        }

                        // fallback to access token
                        return revokeAccessToken(token, requestingClientId);
                    })
                    .onErrorResumeNext(throwable -> {
                        // Note: invalid tokens do not cause an error response since the client
                        // cannot handle such an error in a reasonable way.  Moreover, the
                        // purpose of the revocation request, invalidating the particular token,
                        // is already achieved.
                        // Log the result anyway for posterity.
                        if (throwable instanceof InvalidTokenException) {
                            logger.debug("No access token {} found in the token store.", token);
                            return Completable.complete();
                        }
                        return Completable.error(throwable);
                    });
        }

        // The user didn't hint that this is a refresh token, so it MAY be an access
        // token. If we don't find an access token... check if it's a refresh token.
        return revokeAccessToken(token, requestingClientId)
                .onErrorResumeNext(throwable -> {
                    // if the token was issued to the client making the revocation request
                    // the request is refused and the client is informed of the error
                    if (throwable instanceof InvalidGrantException) {
                        return Completable.error(throwable);
                    }

                    // Note: invalid tokens do not cause an error response since the client
                    // cannot handle such an error in a reasonable way.  Moreover, the
                    // purpose of the revocation request, invalidating the particular token,
                    // is already achieved.
                    // Log the result anyway for posterity.
                    if (throwable instanceof InvalidTokenException) {
                        logger.debug("No access token {} found in the token store.", token);
                    }

                    // fallback to refresh token
                    return revokeRefreshToken(token, requestingClientId);
                })
                .onErrorResumeNext(throwable -> {
                    // Note: invalid tokens do not cause an error response since the client
                    // cannot handle such an error in a reasonable way.  Moreover, the
                    // purpose of the revocation request, invalidating the particular token,
                    // is already achieved.
                    // Log the result anyway for posterity.
                    if (throwable instanceof InvalidTokenException) {
                        logger.debug("No refresh token {} found in the token store.", token);
                        return Completable.complete();
                    }
                    return Completable.error(throwable);
                });

    }

    private Completable revokeAccessToken(String token, String requestingClientId) {
        return tokenService.getAccessToken(token)
                .switchIfEmpty(Maybe.error(new InvalidTokenException()))
                .flatMapCompletable(accessToken -> {
                    String tokenClientId = ((DefaultAccessToken) accessToken).getClientId();
                    if (!requestingClientId.equals(tokenClientId)) {
                        logger.debug("Revoke FAILED: requesting client = {}, token's client = {}.", requestingClientId, tokenClientId);
                        return Completable.error(new InvalidGrantException("Cannot revoke tokens issued to other clients."));
                    }

                    return tokenService.deleteAccessToken(token);
                });
    }

    private Completable revokeRefreshToken(String token, String requestingClientId) {
        return tokenService.getRefreshToken(token)
                .switchIfEmpty(Maybe.error(new InvalidTokenException()))
                .flatMapCompletable(refreshToken -> {
                    if (!requestingClientId.equals(refreshToken.getClientId())) {
                        logger.debug("Revoke FAILED: requesting client = {}, token's client = {}.", requestingClientId, refreshToken.getClientId());
                        return Completable.error(new InvalidGrantException("Cannot revoke tokens issued to other clients."));
                    }

                    return tokenService.deleteRefreshToken(token);
                });
    }
}