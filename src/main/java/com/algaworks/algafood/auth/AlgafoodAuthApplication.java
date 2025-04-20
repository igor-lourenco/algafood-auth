package com.algaworks.algafood.auth;

import com.algaworks.algafood.auth.core.io.Base64ProtocolResolver;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AlgafoodAuthApplication {

	public static void main(String[] args) {

		SpringApplication springApplication = new SpringApplication(AlgafoodAuthApplication.class);

		// Adicionando e registrando o listener Base64ProtocolResolver no contexto da aplicação (ApplicationContext)
		springApplication.addListeners(new Base64ProtocolResolver());

		springApplication.run(args);


//		SpringApplication.run(AlgafoodAuthApplication.class, args);
	}

}
