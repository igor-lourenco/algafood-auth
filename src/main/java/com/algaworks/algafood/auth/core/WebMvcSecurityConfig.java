package com.algaworks.algafood.auth.core;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Essa classe de configuração facilita a configuração de rotas específicas no Spring MVC.
 *  E foi implementado o método addViewControllers da interface WebMvcConfigurer que associa diretamente a rota '/login'
 *  a uma página de visualização */
@Configuration
public class WebMvcSecurityConfig implements WebMvcConfigurer {


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
