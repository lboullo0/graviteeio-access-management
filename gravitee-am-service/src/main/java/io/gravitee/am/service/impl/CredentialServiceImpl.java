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
package io.gravitee.am.service.impl;

import io.gravitee.am.model.Credential;
import io.gravitee.am.repository.management.api.CredentialRepository;
import io.gravitee.am.service.CredentialService;
import io.gravitee.am.service.exception.AbstractManagementException;
import io.gravitee.am.service.exception.TechnicalManagementException;
import io.reactivex.Maybe;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class CredentialServiceImpl implements CredentialService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialServiceImpl.class);

    @Lazy
    @Autowired
    private CredentialRepository credentialRepository;

    @Override
    public Maybe<Credential> findById(String id) {
        LOGGER.debug("Find credential by ID: {}", id);
        return credentialRepository.findById(id)
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a credential using its ID: {}", id, ex);
                    return Maybe.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a credential using its ID: %s", id), ex));
                });
    }

    @Override
    public Single<List<Credential>> findByUsername(String username) {
        LOGGER.debug("Find credential by username: {}", username);
        return credentialRepository.findByUsername(username)
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a credential using its username: {}", username, ex);
                    return Single.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a credential using its username: %s", username), ex));
                });
    }

    @Override
    public Single<List<Credential>> findByCredentialId(String credentialId) {
        LOGGER.debug("Find credential by credential ID: {}", credentialId);
        return credentialRepository.findByCredentialID(credentialId)
                .onErrorResumeNext(ex -> {
                    LOGGER.error("An error occurs while trying to find a credential using its credential ID: {}", credentialId, ex);
                    return Single.error(new TechnicalManagementException(
                            String.format("An error occurs while trying to find a credential using its credential ID: %s", credentialId), ex));
                });
    }

    @Override
    public Single<Credential> create(Credential credential) {
        LOGGER.debug("Create a new credential {}", credential);

        return credentialRepository.create(credential)
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Single.error(ex);
                    }
                    LOGGER.error("An error occurs while trying to create a credential", ex);
                    return Single.error(new TechnicalManagementException("An error occurs while trying to create a credential", ex));
                });
    }

    @Override
    public Single<Credential> update(Credential credential) {
        LOGGER.debug("Update a credential {}", credential);

        return credentialRepository.update(credential)
                .onErrorResumeNext(ex -> {
                    if (ex instanceof AbstractManagementException) {
                        return Single.error(ex);
                    }
                    LOGGER.error("An error occurs while trying to update a credential", ex);
                    return Single.error(new TechnicalManagementException("An error occurs while trying to update a credential", ex));
                });
    }
}
