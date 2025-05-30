package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.log4j.Log4j2;
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

/**Conversor para o tipo de concessão de senha OAuth2(fluxo Password). Este conversor é usado para converter uma solicitação em um objeto de autenticação.
 * O Spring Authorization Server não fornece um conversor para este tipo de concessão. Portanto, precisamos implementá-lo por conta própria.
 */
@Log4j2
public class OAuth2PasswordGrantAuthenticationConverter implements AuthenticationConverter {
    public static final AuthorizationGrantType PASSWORD_GRANT_TYPE = new AuthorizationGrantType("password");

    @Nullable
    @Override // Se o cliente não estiver registrado no banco de dados, ele nem chega aqui e já é retornado o 401 pelo próprio Spring Security
    public Authentication convert(HttpServletRequest request) {

        // pegando o grant_type 'password' que representa o Password flow
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!PASSWORD_GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }
        log.info("O parâmetro grant_type é do tipo 'password'...");

        // Pega as informações do cliente registrado no banco de dados que já foi autenticado pelo Spring Security
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        if (clientPrincipal == null) {
            log.error("Client não encontrado...");
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        log.info("Pegando os parâmetros da requisição");
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // validando o client_id se são iguais
        if (!StringUtils.equals(clientPrincipal.getName(), parameters.getFirst(OAuth2ParameterNames.CLIENT_ID))) {
            log.error("ID do client não corresponde ao ID do client no parâmetro (client_id) da request...");
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_ID,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // validando o client_secret se são iguais
        if (!StringUtils.equals(String.valueOf (clientPrincipal.getCredentials()), parameters.getFirst(OAuth2ParameterNames.CLIENT_SECRET))){
            log.error("Client secret do cliente não corresponde ao client secret no parâmetro (client_secret) da request...");
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_CLIENT, OAuth2ParameterNames.CLIENT_SECRET,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // pegando o scope
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);

        // validando o scope
        if (StringUtils.isNotBlank(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            log.error("O parâmetro (scope) está vazio ou tamanho diferente de 1");
            OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE,
                OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> scopes = scope != null ? Set.of(scope.split(" ")) : null;

        return new OAuth2PasswordGrantAuthenticationTokenModel(parameters.getFirst(OAuth2ParameterNames.USERNAME),
            parameters.getFirst(OAuth2ParameterNames.PASSWORD), clientPrincipal, scopes);
    }
}