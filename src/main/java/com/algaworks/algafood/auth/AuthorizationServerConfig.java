package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**  Essa classe é responsável por configurar o servidor de autorização OAuth2, de como os clientes se autenticam e
  obtêm tokens de acesso.  */
@Configuration
@EnableAuthorizationServer // Habilita a configuração do servidor de autorização OAuth2.
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;


    @Override //  Configurar os detalhes dos clientes OAuth2. (nesse caso o cliente Web, App, etc...)
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients
            .inMemory()  // Armazena os detalhes dos clientes em memória.
                .withClient("algafood-web")  // Define o ID do cliente.
                .secret(passwordEncoder.encode("web123")) // Senha do cliente codificado com PasswordEncoder.
                .authorizedGrantTypes("password") // Tipo de concessão autorizado, passado via grant_type
                .scopes("write", "read")  //  Escopos permitidos.
                .accessTokenValiditySeconds(60 * 60 * 4) // Validade do token de acesso de 4 horas
            .and()
                .withClient("check-token") // outro client
                .secret(passwordEncoder.encode("check123"))
                .authorizedGrantTypes("password")
                .scopes("write", "read");

    }


/** Este método define o AuthenticationManager que será usado para autenticar os usuários que tentam obter um token de
  acesso usando o fluxo de senha (password grant type).

    O AuthenticationManager é um componente que gerencia a autenticação dos usuários. Vai usar este gerenciador específico
 para autenticar os usuários quando eles solicitarem tokens de acesso, garantindo que apenas usuários autenticados
 possam obter tokens de acesso.
*/
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        endpoints.authenticationManager(authenticationManager);

    }


/** Este método configura as políticas de segurança para o servidor de autorização, especificamente para os endpoints que o servidor expõe. */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

//      Define que apenas clientes autenticados podem acessar o endpoint que verifica a validade dos tokens. '/oauth/check_token'
        security.checkTokenAccess("isAuthenticated()");

//      security.checkTokenAccess("permitAll()"); // Define que qualquer um pode acessar o endpoint que verifica a validade dos tokens
    }
}
