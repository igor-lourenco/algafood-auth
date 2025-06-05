package com.algaworks.algafood.auth.utils;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/** Métodos utilitários para os endpoints do protocolo OAuth 2.0. Esta classe vem do Spring Security OAuth2 Authorization Server*/
public final class OAuth2EndpointUtils {
    public static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private OAuth2EndpointUtils() {
    }


/** Converte os parâmetros da requisição para um objeto MultiValueMap<String, String>,
    que é uma estrutura que permite associar múltiplos valores a uma mesma chave */
    public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {

        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }


/** Extrai os parâmetros da requisição apenas se ela corresponder ao fluxo "Authorization Code"
    e com a opção de excluir parâmetros específicos.*/
    static Map<String, Object> getParametersIfMatchesAuthorizationCodeGrantRequest(HttpServletRequest request, String... exclusions) {
        if (!matchesAuthorizationCodeGrantRequest(request)) {
            return Collections.emptyMap();
        }
        Map<String, Object> parameters = new HashMap<>(getParameters(request).toSingleValueMap());
        for (String exclusion : exclusions) {
            parameters.remove(exclusion);
        }
        return parameters;
    }


/**  Verifica se a requisição é compatível com o fluxo de concessão "Authorization Code"*/
    static boolean matchesAuthorizationCodeGrantRequest(HttpServletRequest request) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
            request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
            request.getParameter(OAuth2ParameterNames.CODE) != null;
    }


/** Verifica se a requisição é uma requisição de token OAuth2 usando o fluxo Authorization Code com PKCE*/
    static boolean matchesPkceTokenRequest(HttpServletRequest request) {
        return matchesAuthorizationCodeGrantRequest(request) &&
            request.getParameter(PkceParameterNames.CODE_VERIFIER) != null;
    }


/** Método utilitário para lançar uma exceção específica do Spring Security OAuth2, personalizando o código
    e detalhes do erro conforme os padrões do protocolo OAuth 2.0.*/
    public static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthenticationException(error);
    }

}