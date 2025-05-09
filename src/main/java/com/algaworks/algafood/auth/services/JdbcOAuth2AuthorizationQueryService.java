package com.algaworks.algafood.auth.services;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

public class JdbcOAuth2AuthorizationQueryService implements OAuth2AuthorizationQueryService{

    private final JdbcOperations jdbcOperations;

    // para converter cada linha do resultado da consulta SQL em uma instância da classe RegisteredClient.
    private final RowMapper<RegisteredClient> registeredClientRowMapper;

    private final String LIST_AUTHORIZED_CLIENTS = "SELECT * FROM oauth2_authorization_consent c " +
        "INNER JOIN oauth2_registered_client rc ON rc.id = c.registered_client_id " +
        "WHERE c.principal_name = ? ";

    public JdbcOAuth2AuthorizationQueryService(JdbcOperations jdbcOperations) {
        this.jdbcOperations = jdbcOperations;

//      sempre que a consulta SQL for executada, essa instância será usada para mapear os dados do banco para objetos
        this.registeredClientRowMapper = new JdbcRegisteredClientRepository.RegisteredClientRowMapper();
    }


    @Override
    public List<RegisteredClient> listClientsWithConsent(String principalName) {
        return this.jdbcOperations.query(LIST_AUTHORIZED_CLIENTS, registeredClientRowMapper, principalName );
    }
}