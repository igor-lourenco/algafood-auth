package com.algaworks.algafood.auth.controllers;

import com.algaworks.algafood.auth.services.OAuth2AuthorizationQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.List;

/** Esse controller exibe página de clientes OAuth2 autorizados pelo usuário */
@Controller
@RequiredArgsConstructor
@Log4j2
public class AuthorizedClientsController {

    //  Interface que tem a nossa implementação de busca de clientes autorizado pelo usuário
    private final OAuth2AuthorizationQueryService authorizationQueryService;

    private final RegisteredClientRepository clientRepository;
    private final OAuth2AuthorizationConsentService consentService;
    private final OAuth2AuthorizationService authorizationService;

    @GetMapping("/oauth2/authorized-clients")
    public String clientsList(
        Principal principal, // Objeto que tem as informações do usuário autenticado.
        Model model // Serve para adicionar os atributos para serem usados na exibição da página.
    ) {

        // Busca os clientes que receberam consentimento do usuário
        List<RegisteredClient> registeredClients = authorizationQueryService.listClientsWithConsent(principal.getName());

        // Adiciona informação no objeto Model que será usado para renderizar a página de clientes autorizados : templates/pages/authorized-clients
        model.addAttribute("clients", registeredClients);

        return "pages/authorized-clients";  // referencia da pagina html que está em : templates/pages/authorized-clients no resources da aplicação
    }



    @PostMapping("/oauth2/authorized-clients/revoke")
    public String revoke(
        Principal principal, // Objeto que tem as informações do usuário autenticado.
        Model model, // Serve para adicionar os atributos para serem usados na exibição da página.
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId) {

//      Busca cliente pelo id
        RegisteredClient registeredClient = this.clientRepository.findByClientId(clientId);

        if(null == registeredClient){
            throw new AccessDeniedException(String.format("Cliente %s não encontrado", clientId));
        }

//      Busca o consentimento do cliente concedida pelo usuário
        OAuth2AuthorizationConsent consent = this.consentService.findById(registeredClient.getId(), principal.getName());

//      Busca lista de autorizações do usuário concecidas para o cliente
        List<OAuth2Authorization> oAuth2Authorizations = this.authorizationQueryService.listAuthorizations(principal.getName(), registeredClient.getId());

        if(null != consent){
            log.info("Excluindo consentimento do clienteId: {}", consent.getRegisteredClientId());
            this.consentService.remove(consent);
        }

        for(OAuth2Authorization authorization : oAuth2Authorizations){
            log.info("Excluindo token do id: {}", authorization.getId());
            this.authorizationService.remove(authorization);
        }

        return "redirect:/oauth2/authorized-clients"; // redireciona para pagina html que está em : templates/pages/authorized-clients no resources da aplicação
    }
}