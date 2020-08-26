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
package io.gravitee.am.repository.mongodb.management;

import com.mongodb.reactivestreams.client.MongoCollection;
import io.gravitee.am.common.utils.RandomString;
import io.gravitee.am.model.Credential;
import io.gravitee.am.repository.management.api.CredentialRepository;
import io.gravitee.am.repository.mongodb.management.internal.model.CredentialMongo;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Observable;
import io.reactivex.Single;
import org.bson.Document;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.List;

import static com.mongodb.client.model.Filters.eq;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class MongoCredentialRepository extends AbstractManagementMongoRepository implements CredentialRepository {

    private static final String FIELD_ID = "_id";
    private static final String FIELD_USERNAME = "username";
    private static final String FIELD_CREDENTIAL_ID = "credentialId";
    private MongoCollection<CredentialMongo> credentialsCollection;

    @PostConstruct
    public void init() {
        credentialsCollection = mongoOperations.getCollection("webauthn_credentials", CredentialMongo.class);
        super.createIndex(credentialsCollection, new Document(FIELD_USERNAME, 1));
        super.createIndex(credentialsCollection, new Document(FIELD_CREDENTIAL_ID, 1));
    }

    @Override
    public Single<List<Credential>> findByUsername(String username) {
        return Observable.fromPublisher(credentialsCollection.find(eq(FIELD_USERNAME, username))).map(this::convert).toList();
    }

    @Override
    public Single<List<Credential>> findByCredentialID(String credentialId) {
        return Observable.fromPublisher(credentialsCollection.find(eq(FIELD_CREDENTIAL_ID, credentialId))).map(this::convert).toList();
    }

    @Override
    public Maybe<Credential> findById(String credentialId) {
        return Observable.fromPublisher(credentialsCollection.find(eq(FIELD_ID, credentialId)).first()).firstElement().map(this::convert);
    }

    @Override
    public Single<Credential> create(Credential item) {
        CredentialMongo credential = convert(item);
        credential.setId(credential.getId() == null ? RandomString.generate() : credential.getId());
        return Single.fromPublisher(credentialsCollection.insertOne(credential)).flatMap(success -> findById(credential.getId()).toSingle());
    }

    @Override
    public Single<Credential> update(Credential item) {
        CredentialMongo credential = convert(item);
        return Single.fromPublisher(credentialsCollection.replaceOne(eq(FIELD_ID, credential.getId()), credential)).flatMap(updateResult -> findById(credential.getId()).toSingle());
    }

    @Override
    public Completable delete(String id) {
        return Completable.fromPublisher(credentialsCollection.deleteOne(eq(FIELD_ID, id)));
    }
    private Credential convert(CredentialMongo credentialMongo) {
        if (credentialMongo == null) {
            return null;
        }

        Credential credential = new Credential();
        credential.setId(credentialMongo.getId());
        credential.setUsername(credentialMongo.getUsername());
        credential.setCredentialId(credentialMongo.getCredentialId());
        credential.setPublicKey(credentialMongo.getPublicKey());
        credential.setCounter(credentialMongo.getCounter());
        credential.setCreatedAt(credentialMongo.getCreatedAt());
        credential.setUpdatedAt(credentialMongo.getUpdatedAt());
        return credential;
    }

    private CredentialMongo convert(Credential credential) {
        if (credential == null) {
            return null;
        }

        CredentialMongo credentialMongo = new CredentialMongo();
        credentialMongo.setId(credential.getId());
        credentialMongo.setUsername(credential.getUsername());
        credentialMongo.setCredentialId(credential.getCredentialId());
        credentialMongo.setPublicKey(credential.getPublicKey());
        credentialMongo.setCounter(credential.getCounter());
        credentialMongo.setCreatedAt(credential.getCreatedAt());
        credentialMongo.setUpdatedAt(credential.getUpdatedAt());
        return credentialMongo;
    }
}
