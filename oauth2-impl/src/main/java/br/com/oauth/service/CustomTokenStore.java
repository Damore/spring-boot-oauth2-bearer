package br.com.oauth.service;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;

import br.com.oauth.model.OAuth2AuthenticationAccessToken;
import br.com.oauth.model.OAuth2AuthenticationRefreshToken;


public class CustomTokenStore implements TokenStore {

	// --------------------------------------------
	// Atributos ----------------------------------
	// --------------------------------------------

	private static final Log LOG = LogFactory.getLog(CustomTokenStore.class);

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	private OAuth2AccessTokenService oAuth2AccessTokenService;

	private OAuth2RefreshTokenService oAuth2RefreshTokenService;

	// --------------------------------------------
	// SETTERS ------------------------------------
	// --------------------------------------------

	@Autowired
	public void setoAuth2AccessTokenService(OAuth2AccessTokenService oAuth2AccessTokenService) {
		this.oAuth2AccessTokenService = oAuth2AccessTokenService;
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	@Autowired
	public void setoAuth2RefreshTokenService(OAuth2RefreshTokenService oAuth2RefreshTokenService) {
		this.oAuth2RefreshTokenService = oAuth2RefreshTokenService;
	}

	// --------------------------------------------
	// OVERRIDE -----------------------------------
	// --------------------------------------------

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		OAuth2AccessToken accessToken = null;

		String key = authenticationKeyGenerator.extractKey(authentication);
		try {
			OAuth2AuthenticationAccessToken oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByAuthenticationId(key);
			if (oAuth2AuthenticationAccessToken != null) {
				accessToken = deserializeAccessToken(oAuth2AuthenticationAccessToken.getToken());
			} else {
				throw new EmptyResultDataAccessException(1);
			}
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Failed to find access token for authentication " + authentication);
			}
		} catch (IllegalArgumentException e) {
			LOG.error("Could not extract access token for authentication " + authentication, e);
		}

		if (accessToken != null
				&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			removeAccessToken(accessToken.getValue());
			// Keep the store consistent (maybe the same user is represented by
			// this authentication but the details have
			// changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		String refreshToken = null;
		if (token.getRefreshToken() != null) {
			refreshToken = token.getRefreshToken().getValue();
		}

		if (readAccessToken(token.getValue()) != null) {
			removeAccessToken(token.getValue());
		}
		OAuth2AuthenticationAccessToken oAuth2AuthenticationAccessToken = new OAuth2AuthenticationAccessToken(
				extractTokenKey(token.getValue()), serializeAccessToken(token),
				authenticationKeyGenerator.extractKey(authentication),
				authentication.isClientOnly() ? null : authentication.getName(),
				authentication.getOAuth2Request().getClientId(), serializeAuthentication(authentication),
				extractTokenKey(refreshToken));
		oAuth2AccessTokenService.save(oAuth2AuthenticationAccessToken);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		OAuth2AccessToken accessToken = null;

		try {
			OAuth2AuthenticationAccessToken oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByTokenId(extractTokenKey(tokenValue));
			if (oAuth2AuthenticationAccessToken != null) {
				accessToken = deserializeAccessToken(oAuth2AuthenticationAccessToken.getToken());
			} else {
				throw new EmptyResultDataAccessException(1);
			}
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find access token for token " + tokenValue);
			}
		} catch (IllegalArgumentException e) {
			LOG.warn("Failed to deserialize access token for " + tokenValue, e);
			removeAccessToken(tokenValue);
		}

		return accessToken;
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken token) {
		removeAccessToken(token.getValue());
	}

	public void removeAccessToken(String tokenValue) {
		oAuth2AccessTokenService.deleteByTokenId(extractTokenKey(tokenValue));
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		OAuth2Authentication authentication = null;

		try {
			OAuth2AuthenticationAccessToken oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByTokenId(extractTokenKey(token));
			if (oAuth2AuthenticationAccessToken != null) {
				authentication = deserializeAuthentication(oAuth2AuthenticationAccessToken.getAuthentication());
			} else {
				throw new EmptyResultDataAccessException(1);
			}
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find access token for token " + token);
			}
		} catch (IllegalArgumentException e) {
			LOG.warn("Failed to deserialize authentication for " + token, e);
			removeAccessToken(token);
		}

		return authentication;
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		String tokenKey = extractTokenKey(refreshToken.getValue());
		byte[] serializeRefreshToken = serializeRefreshToken(refreshToken);
		byte[] serializeAuthentication = serializeAuthentication(authentication);

		OAuth2AuthenticationRefreshToken oAuth2AuthenticationRefreshToken = new OAuth2AuthenticationRefreshToken(
				tokenKey, serializeRefreshToken, serializeAuthentication);
		oAuth2RefreshTokenService.save(oAuth2AuthenticationRefreshToken);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String token) {
		OAuth2RefreshToken refreshToken = null;

		try {
			OAuth2AuthenticationRefreshToken oAuth2AuthenticationRefreshToken = oAuth2RefreshTokenService
					.findById(extractTokenKey(token));
			if (oAuth2AuthenticationRefreshToken != null) {
				refreshToken = deserializeRefreshToken(oAuth2AuthenticationRefreshToken.getToken());
			} else {
				throw new EmptyResultDataAccessException(1);
			}
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find refresh token for token " + token);
			}
		} catch (IllegalArgumentException e) {
			LOG.warn("Failed to deserialize refresh token for token " + token, e);
			removeRefreshToken(token);
		}

		return refreshToken;
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken token) {
		removeRefreshToken(token.getValue());
	}

	public void removeRefreshToken(String token) {
		oAuth2RefreshTokenService.deleteById(extractTokenKey(token));
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
		OAuth2Authentication authentication = null;

		try {
			OAuth2AuthenticationRefreshToken oAuth2AuthenticationRefreshToken = oAuth2RefreshTokenService
					.findById(extractTokenKey(value));
			if (oAuth2AuthenticationRefreshToken != null) {
				authentication = deserializeAuthentication(oAuth2AuthenticationRefreshToken.getAuthentication());
			} else {
				throw new EmptyResultDataAccessException(1);
			}
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find access token for token " + value);
			}
		} catch (IllegalArgumentException e) {
			LOG.warn("Failed to deserialize access token for " + value, e);
			removeRefreshToken(value);
		}

		return authentication;
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	public void removeAccessTokenUsingRefreshToken(String refreshToken) {
		oAuth2AccessTokenService.deleteByRefreshToken(extractTokenKey(refreshToken));
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {
			List<OAuth2AuthenticationAccessToken> oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByClientId(clientId);
			accessTokens = extractAccessTokens(oAuth2AuthenticationAccessToken);
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find access token for clientId " + clientId);
			}
		}
		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	public Collection<OAuth2AccessToken> findTokensByUserName(String userName) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {
			List<OAuth2AuthenticationAccessToken> oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByUserName(userName);
			accessTokens = extractAccessTokens(oAuth2AuthenticationAccessToken);
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled())
				LOG.info("Failed to find access token for userName " + userName);
		}
		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();

		try {
			List<OAuth2AuthenticationAccessToken> oAuth2AuthenticationAccessToken = oAuth2AccessTokenService
					.findByUserNameAndClientId(userName, clientId);
			accessTokens = extractAccessTokens(oAuth2AuthenticationAccessToken);
		} catch (EmptyResultDataAccessException e) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Failed to find access token for clientId " + clientId + " and userName " + userName);
			}
		}
		accessTokens = removeNulls(accessTokens);

		return accessTokens;
	}

	private List<OAuth2AccessToken> removeNulls(List<OAuth2AccessToken> accessTokens) {
		List<OAuth2AccessToken> tokens = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AccessToken token : accessTokens) {
			if (token != null) {
				tokens.add(token);
			}
		}
		return tokens;
	}

	protected String extractTokenKey(String value) {
		if (value == null) {
			return null;
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
		}

		try {
			byte[] bytes = digest.digest(value.getBytes("UTF-8"));
			return String.format("%032x", new BigInteger(1, bytes));
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
		}
	}

	// --------------------------------------------
	// SERIALIZE ----------------------------------
	// --------------------------------------------

	protected byte[] serializeAccessToken(OAuth2AccessToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
		return SerializationUtils.serialize(authentication);
	}

	protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
		return SerializationUtils.deserialize(authentication);
	}

	// --------------------------------------------
	// Custom -------------------------------------
	// --------------------------------------------

	private List<OAuth2AccessToken> extractAccessTokens(List<OAuth2AuthenticationAccessToken> tokens) {
		List<OAuth2AccessToken> accessTokens = new ArrayList<OAuth2AccessToken>();
		for (OAuth2AuthenticationAccessToken token : tokens) {
			try {
				accessTokens.add(deserializeAccessToken(token.getToken()));
			} catch (IllegalArgumentException e) {
				oAuth2AccessTokenService.deleteByTokenId(token.getTokenId());// TODO
																				// TESTAR
																				// SE
																				// Precisa
																				// deserealizar
			}
		}
		return accessTokens;
	}

}
