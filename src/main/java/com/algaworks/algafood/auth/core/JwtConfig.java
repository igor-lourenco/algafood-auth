package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.models.UsuarioModel;
import com.algaworks.algafood.auth.properties.JwtKeyStoreProperties;
import com.algaworks.algafood.auth.repositories.UsuarioRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashSet;
import java.util.Set;

@Configuration
@Log4j2
public class JwtConfig {

    @Bean
    //Esse bean é responsável por configurar a fonte de JWKs do aplicativo, carrega as chaves do keystore para serem usadas para autenticar o token
    public JWKSource<SecurityContext> jwkSource(JwtKeyStoreProperties properties) throws Exception {
        log.info(">>> CARREGANDO AS CHAVES DO KEYSTORE PARA AUTENTICAÇÃO DO TOKEN JWT");

        char[] keyStorePass = properties.getPassword().toCharArray();
        String keypairAlias = properties.getKeypairAlias();

        Resource jksLocation = properties.getPath();
        InputStream inputStream = jksLocation.getInputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, keyStorePass);

        RSAKey rsaKey = RSAKey.load(keyStore, keypairAlias, keyStorePass);

        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // Esse bean é responsável por adicionar claims customizadas na geração do token JWT
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(UsuarioRepository userRepository) {
        log.info(">>> CARREGANDO BEAN PARA CUSTOMIZACAO DAS CLAIMS NA GERACAO DO TOKEN JWT");
        return context -> {
            Authentication authentication = context.getPrincipal();
            if (authentication.getPrincipal() instanceof User) {
                User userDetail = (User) authentication.getPrincipal();

                log.info(">>> Buscando no banco de dados o username: {}", userDetail.getUsername());
                UsuarioModel user = userRepository.findByEmail(userDetail.getUsername()).orElseThrow();

                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority authority : userDetail.getAuthorities()) {
                    authorities.add(authority.getAuthority());
                }

                log.info(">>> Adicionando claim customizada user_id: {}", user.getId().toString());
                context.getClaims().claim("user_id", user.getId().toString()); // adiciona o id do usuario no token

                log.info(">>> Adicionando claim customizada nome_usuario: {}", user.getNome());
                context.getClaims().claim("nome_usuario", user.getNome()); // adiciona o id do usuario no token

                log.info(">>> Adicionando claim customizada authorities: {}", authorities);
                context.getClaims().claim("authorities", authorities); // adiciona lista de authorities do usuario no token
            }
        };
    }

}
