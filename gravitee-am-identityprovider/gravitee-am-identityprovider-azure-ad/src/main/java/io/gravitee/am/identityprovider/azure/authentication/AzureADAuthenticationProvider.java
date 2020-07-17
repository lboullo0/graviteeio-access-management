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
package io.gravitee.am.identityprovider.azure.authentication;

import com.nimbusds.jwt.proc.JWTProcessor;
import io.gravitee.am.common.jwt.SignatureAlgorithm;
import io.gravitee.am.common.oidc.Scope;
import io.gravitee.am.identityprovider.api.IdentityProviderMapper;
import io.gravitee.am.identityprovider.api.IdentityProviderRoleMapper;
import io.gravitee.am.identityprovider.api.common.Request;
import io.gravitee.am.identityprovider.api.oidc.OpenIDConnectIdentityProviderConfiguration;
import io.gravitee.am.identityprovider.azure.AzureADIdentityProviderConfiguration;
import io.gravitee.am.identityprovider.azure.AzureADIdentityProviderMapper;
import io.gravitee.am.identityprovider.azure.AzureADIdentityProviderRoleMapper;
import io.gravitee.am.identityprovider.azure.authentication.spring.AzureADAuthenticationProviderConfiguration;
import io.gravitee.am.identityprovider.common.oauth2.authentication.AbstractOpenIDConnectAuthenticationProvider;
import io.gravitee.am.identityprovider.common.oauth2.jwt.jwks.remote.RemoteJWKSourceResolver;
import io.gravitee.am.identityprovider.common.oauth2.jwt.processor.JWKSKeyProcessor;
import io.vertx.reactivex.ext.web.client.WebClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Import;

import java.util.HashSet;

/**
 * @author Eric LELEU (eric.leleu at graviteesource.com)
 * @author GraviteeSource Team
 */
@Import(AzureADAuthenticationProviderConfiguration.class)
public class AzureADAuthenticationProvider extends AbstractOpenIDConnectAuthenticationProvider<AzureADIdentityProviderConfiguration> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AzureADAuthenticationProvider.class);

    private static final String ID_TOKEN_PARAMETER = "id_token";

    public static final String HOST_MICROSOFT_LOGIN = "https://login.microsoftonline.com/";
    public static final String AUTHORIZATION_PATH = "/oauth2/v2.0/authorize";
    public static final String TOKEN_PATH = "/oauth2/v2.0/token";
    public static final String JWKS_PATH = "/discovery/v2.0/keys";

    @Autowired
    @Qualifier("azureAdWebClient")
    private WebClient client;

    @Autowired
    private AzureADIdentityProviderMapper mapper;

    @Autowired
    private AzureADIdentityProviderRoleMapper roleMapper;

    @Autowired
    private AzureADIdentityProviderConfiguration configuration;

    @Override
    public OpenIDConnectIdentityProviderConfiguration getConfiguration() {
        return this.configuration;
    }

    @Override
    protected IdentityProviderMapper getIdentityProviderMapper() {
        return this.mapper;
    }

    @Override
    protected IdentityProviderRoleMapper getIdentityProviderRoleMapper() {
        return this.roleMapper;
    }

    @Override
    protected WebClient getClient() {
        return this.client;
    }

    public void setJwtProcessor(JWTProcessor jwtProcessor) {
        this.jwtProcessor = jwtProcessor;
    }

    @Override
    public Request signInUrl(String redirectUri) {
        forceOpenIdScope();
        return super.signInUrl(redirectUri);
    }

    private void forceOpenIdScope() {
        if (configuration.getScopes() == null) {
            configuration.setScopes(new HashSet<>());
        }
        configuration.getScopes().add(Scope.OPENID.getKey());
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        AzureADIdentityProviderConfiguration configuration = this.configuration;

        // check configuration
        // a client secret is required if authorization code flow is used
        if (io.gravitee.am.common.oauth2.ResponseType.CODE.equals(configuration.getResponseType())
                && (configuration.getClientSecret() == null || configuration.getClientSecret().isEmpty())) {
            throw new IllegalArgumentException("A client_secret must be supplied in order to use the Authorization Code flow");
        }

        // generate jwt processor if we try to fetch user information from the ID Token
        generateJWTProcessor();
    }

    private void generateJWTProcessor() {
        final SignatureAlgorithm signature = SignatureAlgorithm.RS256;
        JWKSKeyProcessor keyProcessor = new JWKSKeyProcessor<>();
        keyProcessor.setJwkSourceResolver(new RemoteJWKSourceResolver(configuration.getResolverParameter()));
        jwtProcessor = keyProcessor.create(signature);
    }
}