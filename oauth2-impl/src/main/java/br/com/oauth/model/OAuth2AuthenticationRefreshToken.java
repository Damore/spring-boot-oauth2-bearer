package br.com.oauth.model;

import java.io.Serializable;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.PersistenceConstructor;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.mongodb.core.mapping.Document;

@TypeAlias("oAuth2AuthenticationRefreshToken")
@Document(collection = "oAuth2AuthenticationRefreshToken")
public class OAuth2AuthenticationRefreshToken implements Serializable {

	/** A Constante serialVersionUID. */
	private static final long serialVersionUID = 1L;

	@Id
	private String tokenId;

	private final byte[] token;

	private final byte[] authentication;

	@PersistenceConstructor
	public OAuth2AuthenticationRefreshToken(final String tokenId, byte[] token, byte[] authentication) {
		this.tokenId = tokenId;
		this.token = token;
		this.authentication = authentication;
	}

	public byte[] getToken() {
		return token;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public String getTokenId() {
		return tokenId;
	}

	public void setTokenId(String tokenId) {
		this.tokenId = tokenId;
	}

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
	}

}
