package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.properties.JwtKeyStoreProperties;
import com.algaworks.algafood.auth.services.enhancers.JwtCustomClaimsTokenEnhancer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.security.KeyPair;
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
    private JwtKeyStoreProperties properties;


    @Override //  Configurar os detalhes dos clientes OAuth2. (nesse caso o cliente Web, App, etc...)
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients
            .inMemory()  // Armazena os detalhes dos clientes em memória.
            .withClient("algafood-web")  // Define o ID do client (esse client está sendo usado pelo postman)
            .secret(passwordEncoder.encode("web123")) // Senha do cliente codificado com PasswordEncoder.
            .authorizedGrantTypes("password", "refresh_token") // Tipo de concessão autorizado, passado via grant_type
            .scopes("WRITE", "READ")  //  Escopos permitidos para os clients.
            .accessTokenValiditySeconds(60 * 60 * 4) // Validade do token de acesso de 4 horas
            .refreshTokenValiditySeconds(60 * 60 * 24) // // Validade do refresh token de acesso de 24 horas

        ;

    }


    /**
     * Este método define o AuthenticationManager que será usado para autenticar os usuários que tentam obter um token de
     * acesso usando o fluxo de senha (por exemplo: password grant type).
     * <p>
     * O AuthenticationManager é um componente que gerencia a autenticação dos usuários. Vai usar este gerenciador específico
     * para autenticar os usuários quando eles solicitarem tokens de acesso, garantindo que apenas usuários autenticados
     * possam obter tokens de acesso.
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        var enhancerChain = new TokenEnhancerChain(); // representa a cadeia de enhancer que serve para personalizar o payload JSON do JWT

        // adiciona a nossa classe de enhancer personalizada, obs: a nossa classe tem que ser a primeira da lista
        enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(),jwtAccessTokenConverter()));


        endpoints
            .authenticationManager(authenticationManager)
            .userDetailsService(userDetailsService)
            .reuseRefreshTokens(false) // para não reutilizar o refresh token
            .accessTokenConverter(jwtAccessTokenConverter()) // Informa para usar o JwtAccessTokenConverter especificado para converter tokens de acesso JWT.
            .tokenEnhancer(enhancerChain)
            .approvalStore(approvalStore(endpoints.getTokenStore()))
            .tokenGranter(tokenGranter(endpoints))// Configura o nosso TokenGranter personalizado para usar a nossa implementação do PKCE
            ;
    }

    @Bean // Usado para converter e validar tokens JWT com uma chave de assinatura específica(chave secreta)
    public JwtAccessTokenConverter jwtAccessTokenConverter(){
        JwtAccessTokenConverter jwtAccessTokenConverter =  new JwtAccessTokenConverter();

//      ---- Dessa forma configura para gerar JWT com chave simétrica ----
//      jwtAccessTokenConverter.setSigningKey("89f35f44-a025-4ed0-bb7e-950c033d9563"); // chave secreta simétrica, por padrão usa o algoritmo "HmacSHA256"

//      ----------------------------------------------------------------------------------------------------------------

//      ---- Dessa forma configura para gerar JWT com chave assimétrica ----
//      Classe para representar um recurso (geralmente um arquivo) localizado no classpath da aplicação.
        ClassPathResource classPathResource = new ClassPathResource(properties.getPath());

        String keyStorePass = properties.getPassword(); // senha que foi criada para abrir o arquivo algafood.jks
        String keyPairAlias = properties.getKeypairAlias(); // é o nome do par de chaves especificado criado no parâmetro: -alias

//      A classe KeyStoreKeyFactory é utilizada para carregar e manipular informações de um keystore.
//      Um keystore é um armazenamento seguro que contém pares de chaves (chave pública e chave privada),
//      certificados e outras informações relacionadas à criptografia.
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(classPathResource, keyStorePass.toCharArray());

        KeyPair keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias); //Extrai o par de chaves específico do keyStoreKeyFactory usando o alias fornecido.

        jwtAccessTokenConverter.setKeyPair(keyPair); // Configura o par de chaves extraído no jwtAccessTokenConverter.

        return jwtAccessTokenConverter;
    }



    /**
     * Este método configura as políticas de segurança para o servidor de autorização, especificamente para os endpoints que o servidor expõe.
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

//      Define que apenas clientes autenticados podem acessar o endpoint que verifica a validade dos tokens. '/oauth/check_token'
        security.checkTokenAccess("isAuthenticated()");
//      security.checkTokenAccess("permitAll()"); // Define que qualquer um pode acessar o endpoint que verifica a validade dos tokens


        // libera a API que retorna a chave pública mas apenas para os clientes autenticados que terão acesso: '/oauth/token_key'
        security.tokenKeyAccess("isAuthenticated()");
    }


    /**
     * Configura um TokenGranter composto que inclui suporte para PKCE (via PkceAuthorizationCodeTokenGranter)
     * além dos outros TokenGranter padrão configurado nos endpoints do servidor de autorização, passados como parâmetro via grant_type
     */
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


//  Para o fluxo de aprovação do Authorization Code com JWT
    private ApprovalStore approvalStore(TokenStore tokenStore){
        var approvalStore = new TokenApprovalStore();
        approvalStore.setTokenStore(tokenStore);

        return approvalStore;
    }
}

