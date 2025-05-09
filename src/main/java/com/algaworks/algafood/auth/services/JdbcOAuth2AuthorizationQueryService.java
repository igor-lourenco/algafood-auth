package com.algaworks.algafood.auth.services;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.List;

public class JdbcOAuth2AuthorizationQueryService implements OAuth2AuthorizationQueryService{
    private final String LIST_AUTHORIZED_CLIENTS = "SELECT * FROM oauth2_authorization_consent c " +
        "INNER JOIN oauth2_registered_client rc ON rc.id = c.registered_client_id " +
        "WHERE c.principal_name = ? ";

    private final String LIST_AUTHORIZATIONS_BY_PRINCIPAL_NAME_AND_CLIENT_ID_QUERY = "SELECT a.* FROM oauth2_authorization a " +
        "INNER JOIN oauth2_registered_client rc ON rc.id = a.registered_client_id " +
        "WHERE a.principal_name = ? " +
        "AND a.registered_client_id = ?";

    private final JdbcOperations jdbcOperations;

    // para converter cada linha do resultado da consulta SQL em uma instância da classe RegisteredClient.
    private final RowMapper<RegisteredClient> registeredClientRowMapper;

    // para converter cada linha do resultado da consulta SQL em uma instância da classe OAuth2Authorization.
    private final RowMapper<OAuth2Authorization> oAuth2AuthorizationRowMapper;

    public JdbcOAuth2AuthorizationQueryService(JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
        this.jdbcOperations = jdbcOperations;

//      sempre que a consulta SQL for executada, essa instância será usada para mapear os dados do banco para objetos
        this.registeredClientRowMapper = new JdbcRegisteredClientRepository.RegisteredClientRowMapper();

//      sempre que a consulta SQL for executada, essa instância será usada para mapear os dados do banco para objetos
        this.oAuth2AuthorizationRowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(repository);
    }


    @Override
    public List<RegisteredClient> listClientsWithConsent(String principalName) {
        return this.jdbcOperations.query(LIST_AUTHORIZED_CLIENTS, registeredClientRowMapper, principalName );
    }


    @Override
    public List<OAuth2Authorization> listAuthorizations(String principalName, String clientId) {
        return this.jdbcOperations.query(LIST_AUTHORIZATIONS_BY_PRINCIPAL_NAME_AND_CLIENT_ID_QUERY, oAuth2AuthorizationRowMapper
            , principalName, clientId);
    }
}