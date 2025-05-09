package com.algaworks.algafood.auth.controllers;

import com.algaworks.algafood.auth.services.OAuth2AuthorizationQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.List;

/** Esse controller exibe página de clientes OAuth2 autorizados pelo usuário */
@Controller
@RequiredArgsConstructor
public class AuthorizedClientsController {

    //  Interface que tem a nossa implementação de busca de clientes autorizado pelo usuário
    private final OAuth2AuthorizationQueryService oAuth2AuthorizationQueryService;

    @GetMapping("/oauth2/authorized-clients")
    public String clientsList(
        Principal principal, // Objeto que tem as informações do usuário autenticado.
        Model model // Serve para adicionar os atributos para serem usados na exibição da página.
    ) {

        // Busca os clientes que receberam consentimento do usuário
        List<RegisteredClient> registeredClients = oAuth2AuthorizationQueryService.listClientsWithConsent(principal.getName());

        // Adiciona informação no objeto Model que será usado para renderizar a página de clientes autorizados : templates/pages/authorized-clients
        model.addAttribute("clients", registeredClients);

        return "pages/authorized-clients";  // referencia da pagina html que está em : templates/pages/authorized-clients no resources da aplicação
    }
}