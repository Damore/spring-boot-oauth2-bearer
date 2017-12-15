package br.com.oauth.repository;

import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.oauth.model.OAuth2AuthenticationRefreshToken;

public interface OAuth2RefreshTokenRepository
		extends MongoRepository<OAuth2AuthenticationRefreshToken, String>, OAuth2RefreshTokenRepositoryCustom {

	OAuth2AuthenticationRefreshToken findByTokenId(String tokenId);

	void deleteByTokenId(String tokenId);

}