package com.algaworks.algafood.auth.services;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

/** Essa interface serve para recuperar os clientes que receberam autorização para acessar recursos protegidos em nome de um usuário */
public interface OAuth2AuthorizationQueryService {

    /**  Consulta os clientes registrados que já receberam o consentimento pelo usuário 'principalName'*/
    List<RegisteredClient> listClientsWithConsent(String principalName);
}