package br.com.oauth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Service;

import br.com.oauth.model.CustomClientDetails;
import br.com.oauth.repository.CustomClientDetailsRepository;

@Service
public class CustomClientDetailsService implements ClientDetailsService, ClientRegistrationService {

	@Autowired
	private CustomClientDetailsRepository repository;

	@Override
	@CacheEvict(value = "clientDetails", allEntries = true)
	public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
		repository.save((CustomClientDetails) clientDetails);
	}

	@Override
	@CacheEvict(value = "clientDetails", allEntries = true)
	public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
		// TODO Auto-generated method stub
	}

	@Override
	@CacheEvict(value = "clientDetails", allEntries = true)
	public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
		// TODO Auto-generated method stub
	}

	@Override
	@CacheEvict(value = "clientDetails", allEntries = true)
	public void removeClientDetails(String clientId) throws NoSuchClientException {
		// TODO Auto-generated method stub
	}

	@Override
	@Cacheable(value = "clientDetails")
	public List<ClientDetails> listClientDetails() {
		return new ArrayList<ClientDetails>(repository.findAll());
	}

	@Override
	// @Cacheable(value="clientDetails", key="#clientId")
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		return repository.findById(clientId);
	}

}