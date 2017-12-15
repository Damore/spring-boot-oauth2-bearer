package br.com.oauth.config;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeuRecurso {
	
	
	@GetMapping("/hello")
	public void hello(){
		System.out.println("Hello world!");
	}

}
