package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.cache.CacheProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Arrays;

/**  Essa classe é responsável por configurar o servidor de autorização OAuth2, de como os clientes se autenticam e
  obtêm tokens de acesso.  */
@Configuration
@EnableAuthorizationServer // Habilita a configuração do servidor de autorização OAuth2.
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;


    @Override //  Configurar os detalhes dos clientes OAuth2. (nesse caso o cliente Web, App, etc...)
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients
            .inMemory()  // Armazena os detalhes dos clientes em memória.
                .withClient("algafood-web")  // Define o ID do client (esse client está sendo usado pelo postman)
                .secret(passwordEncoder.encode("web123")) // Senha do cliente codificado com PasswordEncoder.
                .authorizedGrantTypes("password", "refresh_token") // Tipo de concessão autorizado, passado via grant_type
                .scopes("write", "read")  //  Escopos permitidos.
                .accessTokenValiditySeconds(60 * 60 * 4) // Validade do token de acesso de 4 horas
                .refreshTokenValiditySeconds(60 * 60 * 24) // // Validade do refresh token de acesso de 24 horas

            .and()
                .withClient("check-token") // outro client (esse client está sendo usado pelo algafood-api)
                .secret(passwordEncoder.encode("check123"))
                .authorizedGrantTypes("password")
                .scopes("write", "read")

            .and()
            .withClient("foodanalitics") // outro client
            .secret(passwordEncoder.encode("food123"))
            .authorizedGrantTypes("authorization_code") // Tipo de concessão autorizado, passado via grant_type
            .scopes("write", "read")
            .redirectUris("http://aplicacao_cliente")
        ;

    }


/** Este método define o AuthenticationManager que será usado para autenticar os usuários que tentam obter um token de
  acesso usando o fluxo de senha (por exemplo: password grant type).

    O AuthenticationManager é um componente que gerencia a autenticação dos usuários. Vai usar este gerenciador específico
 para autenticar os usuários quando eles solicitarem tokens de acesso, garantindo que apenas usuários autenticados
 possam obter tokens de acesso.
*/
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        endpoints
            .authenticationManager(authenticationManager)
            .userDetailsService(userDetailsService)
            .reuseRefreshTokens(false) // para não reutilizar o refresh token
            .tokenStore(redisTokenStore()) // Configura onde os tokens de autenticação serão armazenados.
            .tokenGranter(tokenGranter(endpoints));// Configura o nosso TokenGranter personalizado para usar a nossa implementação do PKCE
    }


/** Este método configura as políticas de segurança para o servidor de autorização, especificamente para os endpoints que o servidor expõe. */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

//      Define que apenas clientes autenticados podem acessar o endpoint que verifica a validade dos tokens. '/oauth/check_token'
        security.checkTokenAccess("isAuthenticated()");

//      security.checkTokenAccess("permitAll()"); // Define que qualquer um pode acessar o endpoint que verifica a validade dos tokens
    }


/** Configura um TokenGranter composto que inclui suporte para PKCE (via PkceAuthorizationCodeTokenGranter)
    além dos outros TokenGranter padrão configurado nos endpoints do servidor de autorização, passados como parâmetro via grant_type */
    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {

       //criado nosso objeto PkceAuthorizationCodeTokenGranter, passando os serviços necessários
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
            endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
            endpoints.getOAuth2RequestFactory());

        //Lista de TokenGranter é criada contendo o nosso PkceAuthorizationCodeTokenGranter recém-criado e o TokenGranter padrão obtido do endpoints.
        var granters = Arrays.asList(
            pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

//      CompositeTokenGranter combina múltiplos TokenGranters em um único TokenGranter.
        return new CompositeTokenGranter(granters);
    }


/** Retorna uma instância com as configurações de conexão com banco Redis para armazenamento dos tokens */
    private TokenStore redisTokenStore(){
        return new RedisTokenStore(redisConnectionFactory);
    }
}
