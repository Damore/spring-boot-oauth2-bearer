package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.oauth.model.Usuario;
import br.com.oauth.repository.UsuarioRepository;

@Service
public class UsuarioService {

	@Autowired
	private UsuarioRepository repository;

	public Usuario findById(String id) {
		return repository.findById(id);
	}

	public void save(Usuario usuario) {
		usuario.setEnabled(true);
		repository.save(usuario);
	}

}
