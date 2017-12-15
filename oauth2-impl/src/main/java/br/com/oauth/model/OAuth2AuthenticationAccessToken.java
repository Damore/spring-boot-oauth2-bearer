package br.com.oauth.model;

import java.io.Serializable;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.mongodb.core.mapping.Document;

@TypeAlias("oAuth2AuthenticationAccessToken")
@Document(collection = "oAuth2AuthenticationAccessToken")
public class OAuth2AuthenticationAccessToken implements Serializable{

    private static final long serialVersionUID = 1L;

    @Id
    private String tokenId;
    
    private byte[] token;

    private String authenticationId;

    private String userName;

    private String clientId;

    private byte[] authentication;

    private String refreshToken;

    public OAuth2AuthenticationAccessToken() {
    }

    public OAuth2AuthenticationAccessToken(final String tokenId, final byte[] token, String authenticationId,
      String userName, String clientId, byte[] authentication, String refreshToken) {
      this.tokenId = tokenId;
    this.token = token;
    this.authenticationId = authenticationId;
    this.userName = userName;
    this.clientId = clientId;
    this.authentication = authentication;
    this.refreshToken = refreshToken;
  }

    public String getTokenId() {
    return tokenId;
  }

  public void setTokenId(String tokenId) {
    this.tokenId = tokenId;
  }

  public byte[] getToken() {
    return token;
  }

  public String getAuthenticationId() {
        return authenticationId;
    }
    
    public String getUserName() {
        return userName;
    }

    public String getClientId() {
        return clientId;
    }

    public byte[] getAuthentication() {
        return authentication;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
    
    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
    }
}