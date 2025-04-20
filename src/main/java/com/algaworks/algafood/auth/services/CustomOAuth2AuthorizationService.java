package com.algaworks.algafood.auth.services;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

public class CustomOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {

    public CustomOAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        super(jdbcOperations, registeredClientRepository);
    }


    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2Authorization authorization = super.findByToken(token, tokenType);

        System.out.println("ADICIONANDO CLAIMS PARA RETORNAR NO JSON");

        if (authorization != null) {
            // Adiciona atributos personalizados
            authorization = OAuth2Authorization.from(authorization)
                .attribute("tenantId", "123456")
                .attribute("userRole", "ADMIN")
                .build();
        }
        return authorization;
    }


    @Override
    public void save(OAuth2Authorization authorization) {

        System.out.println("ADICIONANDO CLAIMS NO BANCO");

        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
            .attribute("authorized_scopes", "123456") // adiciona na coluna attributes da tabela 'oauth2_authorization'
            .build();
        super.save(updatedAuthorization);
    }
}