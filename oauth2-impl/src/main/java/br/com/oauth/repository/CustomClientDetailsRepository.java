package br.com.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.security.oauth2.provider.ClientDetails;

import br.com.oauth.model.CustomClientDetails;

public interface CustomClientDetailsRepository
		extends MongoRepository<CustomClientDetails, String>, CustomClientDetailsRepositoryCustom {

	ClientDetails findById(String id);

}