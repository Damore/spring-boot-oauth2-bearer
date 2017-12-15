package br.com.oauth.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.oauth.model.OAuth2AuthenticationAccessToken;
import br.com.oauth.repository.OAuth2AccessTokenRepository;

@Service
public class OAuth2AccessTokenService {

	@Autowired
	private OAuth2AccessTokenRepository repository;

	public OAuth2AuthenticationAccessToken findByAuthenticationId(String authenticationId) {
		return repository.findByAuthenticationId(authenticationId);
	}

	public void deleteByTokenId(String tokenId) {
		repository.deleteByTokenId(tokenId);
	}

	public void save(OAuth2AuthenticationAccessToken oAuth2AuthenticationAccessToken) {
		repository.save(oAuth2AuthenticationAccessToken);
	}

	public OAuth2AuthenticationAccessToken findByTokenId(String tokenId) {
		return repository.findByTokenId(tokenId);
	}

	public List<OAuth2AuthenticationAccessToken> findByClientId(String clientId) {
		return repository.findByClientId(clientId);
	}

	public List<OAuth2AuthenticationAccessToken> findByUserName(String userName) {
		return repository.findByUserName(userName);
	}

	public List<OAuth2AuthenticationAccessToken> findByUserNameAndClientId(String userName, String clientId) {
		return repository.findByUserNameAndClientId(userName, clientId);
	}

	public void deleteByRefreshToken(String refreshToken) {
		repository.deleteByRefreshToken(refreshToken);
	}

	public void deleteByUserNameAndClientId(String userName, String clientId) {
		repository.deleteByUserNameAndClientId(userName, clientId);
	}

}