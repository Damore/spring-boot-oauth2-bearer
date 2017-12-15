package br.com.oauth.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.oauth.model.OAuth2AuthenticationAccessToken;


public interface OAuth2AccessTokenRepository
		extends MongoRepository<OAuth2AuthenticationAccessToken, String>, OAuth2AccessTokenRepositoryCustom {

	OAuth2AuthenticationAccessToken findByAuthenticationId(String authenticationId);

	void deleteByTokenId(String tokenId);

	OAuth2AuthenticationAccessToken findByTokenId(String tokenId);

	List<OAuth2AuthenticationAccessToken> findByClientId(String clientId);

	List<OAuth2AuthenticationAccessToken> findByUserName(String userName);

	List<OAuth2AuthenticationAccessToken> findByUserNameAndClientId(String userName, String clientId);

	void deleteByRefreshToken(String refreshToken);

	void deleteByUserNameAndClientId(String userName, String clientId);

}