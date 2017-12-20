package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.oauth.model.UsuarioCustom;
import br.com.oauth.repository.UsuarioCustomRepository;

@Service
public class UsuarioCustomService {

	@Autowired
	private UsuarioCustomRepository repository;

	public UsuarioCustom findById(String id) {
		return repository.findById(id);
	}

	public void save(UsuarioCustom usuario) {
		usuario.setEnabled(true);
		repository.save(usuario);
	}

}
