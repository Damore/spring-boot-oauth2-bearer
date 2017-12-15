package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.oauth.model.OAuth2AuthenticationRefreshToken;
import br.com.oauth.repository.OAuth2RefreshTokenRepository;

@Service
public class OAuth2RefreshTokenService {

	@Autowired
	private OAuth2RefreshTokenRepository repository;

	public OAuth2AuthenticationRefreshToken findById(String id) {
		return repository.findByTokenId(id);
	}

	public void save(OAuth2AuthenticationRefreshToken oAuth2AuthenticationRefreshToken) {
		repository.save(oAuth2AuthenticationRefreshToken);
	}

	public void deleteById(String id) {
		repository.deleteByTokenId(id);
	}
}