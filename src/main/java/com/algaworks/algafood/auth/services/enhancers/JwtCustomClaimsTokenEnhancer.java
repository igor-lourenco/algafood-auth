package com.algaworks.algafood.auth.services.enhancers;

import com.algaworks.algafood.auth.services.AuthUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

/** Essa classe permite adicionar nossas informações personalizadas ao token, como claims personalizados.
 *
 * TokenEnhancer - essa interface é usada pelo Spring Security para personalizar um token de acesso antes de ser
 *   criptografado e assinado(Stateless), ou antes, de ele ser armazenado pelo servidor de autorização(StateFul)
 *
 * Claims - São as propriedades do payload JSON do JWT, por exemplo: 'user_name', 'client_id', 'exp'
 * */
public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {


    @Override //Este método permite adicionar informações adicionais ao token, como claims personalizados, que podem ser úteis para autenticação e autorização
    public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
//   OAuth2AccessToken - representa o token antes de ser criptografado, assinado e emitido
//   OAuth2Authentication - representa as informações da autenticação e os dados do cliente autenticado

//      Verifica se é uma instância da nossa classe AuthUser para evitar exception porque nem todos os fluxos fazem a autenticação do usuario final, por exemplo o Client Credentials(client_credentials)
        if(oAuth2Authentication.getPrincipal() instanceof AuthUser) {

            AuthUser authUser = (AuthUser) oAuth2Authentication.getPrincipal(); // contém informações detalhadas sobre o usuário

            var info = new HashMap<String, Object>();
            info.put("nome_completo", authUser.getFullName());
            info.put("usuario_id", authUser.getUserId());


            var accessToken = (DefaultOAuth2AccessToken) oAuth2AccessToken; // cast para a classe que implementa a interface OAuth2AccessToken

            accessToken.setAdditionalInformation(info); // adiciona nossas informações adicionais(claims) ao token
        }


        return oAuth2AccessToken;
    }
}
