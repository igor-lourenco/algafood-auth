package com.algaworks.algafood.auth.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Esse controller exibe página de consentimento de autorização para o cliente OAuth2*/
@Controller
@RequiredArgsConstructor
public class AuthorizationConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService consentService;


    @GetMapping("/oauth2/consent")
    public String consent(
        Principal principal, // usuário autenticado
        Model model,  // Serve para adiciona atributos para serem usados na exibição da página.
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
        @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
        @RequestParam(OAuth2ParameterNames.STATE) String state
    ){

//      Busca o cliente registrado usando o clientId fornecido na solicitação
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        if(null == registeredClient){
            throw new AccessDeniedException(String.format("Cliente de %s não foi encontrado", clientId));
        }

//      Busca o consentimentos aprovados
        OAuth2AuthorizationConsent consent = this.consentService.findById(registeredClient.getId(), principal.getName());

        String[] scopeArray = StringUtils.delimitedListToStringArray(scope, " "); // converte os scopes vindos como parametro em um array
        Set<String> scopesParaAprovar = new HashSet<>(Set.of(scopeArray)); // converte o array em um Set mutável para poder modificar

        Set<String> scopesAprovadosAnteriormente;


        if(null != consent){
//          scopes que já foi aprovado anteriormente
            scopesAprovadosAnteriormente = consent.getScopes();

//          remove os scopes que já foram aprovados anteriormente para adicionar na tela de consentimento as permissões que ainda não foram aprovadas
            scopesParaAprovar.removeAll(scopesAprovadosAnteriormente);
        }else{
            scopesAprovadosAnteriormente = Collections.emptySet();
        }


//      Adiciona informações no objeto Model que será usado para renderizar a página de consentimento: templates/pages/approval
        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("scopesParaAprovar", scopesParaAprovar);
        model.addAttribute("scopesAprovadosAnteriormente", scopesAprovadosAnteriormente);

        return "pages/approval"; // referencia da pagina html que está em : templates/pages/approval no resources da aplicação
    }

}