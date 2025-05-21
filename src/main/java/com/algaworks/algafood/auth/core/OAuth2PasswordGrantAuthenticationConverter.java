package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import com.algaworks.algafood.auth.utils.OAuth2EndpointUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;

import java.util.Set;

/**
 * Conversor para o tipo de concessão de senha OAuth2. Este conversor é usado para converter uma solicitação em um objeto de autenticação.
 * O Spring Authorization Server não fornece um conversor para este tipo de concessão. Portanto, precisamos implementá-lo por conta própria.
 *
 * @author Attoumane AHAMADI
 */
public class OAuth2PasswordGrantAuthenticationConverter implements AuthenticationConverter {
    public static final AuthorizationGrantType PASSWORD_GRANT_TYPE = new AuthorizationGrantType("password");

    @Nullable
    @Override // Se o cliente não estiver registrado no banco de dados, ele nem chega aqui e já é retornado o 401 pelo próprio Spring Security
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!PASSWORD_GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }

        // Pega as informações do cliente registrado no banco de dados que já foi autenticado pelo Spring Security
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        if (clientPrincipal == null) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // Pega os parâmetros da requisição
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // Se o ID do cliente não corresponder ao ID do cliente na solicitação, lança exception
        if (!StringUtils.equals(clientPrincipal.getName(), parameters.getFirst(OAuth2ParameterNames.CLIENT_ID))) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.isNotBlank(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> scopes = scope != null ? Set.of(scope.split(" ")) : null;

        return new OAuth2PasswordGrantAuthenticationTokenModel(parameters.getFirst(OAuth2ParameterNames.USERNAME),
            parameters.getFirst(OAuth2ParameterNames.PASSWORD), clientPrincipal, scopes);
    }
}