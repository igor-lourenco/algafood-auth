package com.algaworks.algafood.auth.core;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

///**  Essa classe configura a segurança da aplicação web em geral, definindo usuários, codificando senhas
//  com BCrypt e fornecendo um gerenciador de autenticação.  */
//@EnableWebSecurity  //  Habilita a configuração de segurança da web no Spring Security.
@Configuration
public class WebSecurityConfig  implements WebMvcConfigurer {


    // Permite registrar controladores de visualização (view controllers) sem lógica adicional
    @Override // Isso elimina a necessidade de escrever um controlador manual para esse endpoint tornando o código mais enxuto
    public void addViewControllers(ViewControllerRegistry registry) {

//      Registra que o caminho /login deve ser tratado por um controlador que simplesmente exibe a página
//      chamada pages/login que está em: templates/pages/login da aplicação
        registry.addViewController("/login").setViewName("pages/login");

//      Define a ordem de prioridade para este registro, garantindo que seja aplicado antes de outros mapeamentos configurados
        registry.setOrder(Ordered.HIGHEST_PRECEDENCE);

    }
}
