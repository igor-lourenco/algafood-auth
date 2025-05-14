package com.algaworks.algafood.auth.models;

import lombok.Data;
import lombok.EqualsAndHashCode;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "TB_USUARIO")
@Data
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class UsuarioModel implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "NOME")
    private String nome;

    @Column(name = "EMAIL")
    private String email;

    @Column(name = "SENHA")
    private String senha;

//    @CreationTimestamp
//    @Column(name = "data_cadastro", nullable = false, columnDefinition = "datetime")
//    private LocalDateTime dataCadastro;

//    @JsonIgnore
    @ManyToMany
    @JoinTable(name = "TB_USUARIO_GRUPO", // específica o nome da tabela que vai ser criada para mapear as associações
        joinColumns = @JoinColumn(name = "usuario_id"), // id da própria classe
        inverseJoinColumns = @JoinColumn(name = "grupo_id") // id da outra tabela
    )
    private Set<GrupoModel> grupos = new HashSet<>();

//    public Boolean associaGrupo(GrupoModel grupoModel){
//        return grupos.add(grupoModel);
//    }
//    public Boolean desassociaGrupo(GrupoModel grupoModel){
//        return grupos.remove(grupoModel);
//    }

}
