package br.com.oauth.model;

import java.util.Collection;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.joda.time.DateTime;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Document
public class Usuario implements UserDetails {

	private static final long serialVersionUID = 1L;

	@Id
	private String id;

	/** O(a) data alteracao. */
	@LastModifiedDate
	private DateTime dataAlteracao;

	/** O(a)(s) cliente id. */
	private Long compradorId;

	/** O(a)(s) enabled. */
	private Boolean enabled = Boolean.TRUE;

	/** O(a)(s) data expiracao credencial. */
	private DateTime dataExpiracaoCredencial;

	/** O(a)(s) data expiracao conta. */
	private DateTime dataExpiracaoConta;

	/** O(a)(s) account non locked. Bloqueia com tentativa de ataque. */
	private Boolean accountNonLocked;

	/** O(a)(s) password. */
	private String password;

	/** O(a)(s) nome. */
	private String nome;

	/** O(a)(s) sobrenome. */
	private String sobrenome;

	private String userName;

	private String cpf;

	private String email;

	private String fieldToSort;

	/** O(a)(s) authorities. */
	private Collection<? extends GrantedAuthority> authorities;

	public String getId() {
		return id;
	}

	// -------------------------------------------------------------------------------------------//
	// ----------------------------------------- PASSWORD
	// ----------------------------------------//
	// -------------------------------------------------------------------------------------------//

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.security.core.userdetails.UserDetails#getPassword()
	 */
	@Override
	public String getPassword() {
		return this.password;
	}

	/**
	 * Define o valor do(a)(s) password.
	 *
	 * @param password
	 *            o novo valor do(a)(s) password
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	// -------------------------------------------------------------------------------------------//
	// -------------------------------------- IDENTIFICADOR
	// --------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.security.core.userdetails.UserDetails#getUsername()
	 */
	@Override
	public String getUsername() {
		return this.getId();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * br.com.silvanopessoa.rest.model.base.AbstractPersistable#setId(java.io.
	 * Serializable)
	 */
	public void setId(String id) {
		this.id = id;
	}

	// -------------------------------------------------------------------------------------------//
	// ----------------------------------- EXPIRAÇÃO DA CONTA
	// ------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.core.userdetails.UserDetails#
	 * isAccountNonExpired()
	 */
	@Override
	public boolean isAccountNonExpired() {
		return dataExpiracaoConta == null || DateTime.now().isBefore(dataExpiracaoConta);
	}

	/**
	 * Define o valor do(a)(s) data expiracao conta.
	 *
	 * @param dataExpiracaoConta
	 *            o novo valor do(a)(s) data expiracao conta
	 */
	public void setDataExpiracaoConta(DateTime dataExpiracaoConta) {
		this.dataExpiracaoConta = dataExpiracaoConta;
	}

	// -------------------------------------------------------------------------------------------//
	// --------------------------------------- BLOQUEADO
	// -----------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.core.userdetails.UserDetails#
	 * isAccountNonLocked()
	 */
	@Override
	public boolean isAccountNonLocked() {
		if (accountNonLocked == null) {
			throw new IllegalStateException("Informações sobre a situação da conta bloqueada não encontrado.");
		}
		return accountNonLocked;
	}

	/**
	 * Define o valor do(a)(s) account non locked.
	 *
	 * @param accountNonLocked
	 *            o novo valor do(a)(s) account non locked
	 */
	public void setAccountNonLocked(Boolean accountNonLocked) {
		this.accountNonLocked = accountNonLocked;
	}

	// -------------------------------------------------------------------------------------------//
	// --------------------------------------- CREDENCIAL
	// ----------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.core.userdetails.UserDetails#
	 * isCredentialsNonExpired()
	 */
	@Override
	public boolean isCredentialsNonExpired() {
		return dataExpiracaoCredencial == null || DateTime.now().isBefore(dataExpiracaoCredencial);
	}

	/**
	 * Define o valor do(a)(s) data expiracao credencial.
	 *
	 * @param dataExpiracaoCredencial
	 *            o novo valor do(a)(s) data expiracao credencial
	 */
	public void setDataExpiracaoCredencial(DateTime dataExpiracaoCredencial) {
		this.dataExpiracaoCredencial = dataExpiracaoCredencial;
	}

	// -------------------------------------------------------------------------------------------//
	// ----------------------------------------- ATIVO
	// -------------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.springframework.security.core.userdetails.UserDetails#isEnabled()
	 */
	@Override
	public boolean isEnabled() {
		if (enabled == null) {
			throw new IllegalStateException("Informações sobre a ativação do usuário não encontrado.");
		}
		return enabled;
	}

	/**
	 * Define o valor do(a)(s) enabled.
	 *
	 * @param enabled
	 *            o novo valor do(a)(s) enabled
	 */
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}

	// -------------------------------------------------------------------------------------------//
	// ----------------------------------------- NOME
	// --------------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/**
	 * Obtém o valor do(a)(s) nome.
	 *
	 * @return O(a)(s) nome
	 */
	public String getNome() {
		return nome;
	}

	/**
	 * Define o valor do(a)(s) nome.
	 *
	 * @param nome
	 *            o novo valor do(a)(s) nome
	 */
	public void setNome(String nome) {
		this.nome = nome;
	}

	// -------------------------------------------------------------------------------------------//
	// -------------------------------------- SOBRENOME
	// ------------------------------------------//
	// -------------------------------------------------------------------------------------------//

	/**
	 * Obtém o valor do(a)(s) sobrenome.
	 *
	 * @return the sobrenome
	 */
	public String getSobrenome() {
		return sobrenome;
	}

	/**
	 * Define o valor do(a)(s) sobrenome.
	 *
	 * @param sobrenome
	 *            the new sobrenome
	 */
	public void setSobrenome(String sobrenome) {
		this.sobrenome = sobrenome;
	}

	// -------------------------------------------------------------------------------------------//
	// --------------------------------- TO_STRING/EQUALS/HASHCODE
	// -------------------------------//
	// -------------------------------------------------------------------------------------------//

	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	public Long getCompradorId() {
		return compradorId;
	}

	public void setCompradorId(Long compradorId) {
		this.compradorId = compradorId;
	}

	public DateTime getDataAlteracao() {
		return dataAlteracao;
	}

	public void setDataAlteracao(DateTime dataAlteracao) {
		this.dataAlteracao = dataAlteracao;
	}

	public String getCpf() {
		return cpf;
	}

	public void setCpf(String cpf) {
		this.cpf = cpf;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getFieldToSort() {
		return fieldToSort;
	}

	public void setFieldToSort(String fieldToSort) {
		this.fieldToSort = fieldToSort;
	}

}