package com.algaworks.algafood.auth.mixin;

import com.algaworks.algafood.auth.models.OAuth2PasswordGrantAuthenticationTokenModel;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/** Essa classe é um desserializador customizado do Jackson para a classe implementada OAuth2PasswordGrantAuthenticationTokenModel.
 * Converte o JSON(que está salvo no banco de dados na tabela 'oauth2_authorization' do Spring Authorization Server, por exemplo)
 * para objeto Java da classe OAuth2PasswordGrantAuthenticationTokenModel, é usada na autenticação OAuth2 com o tipo de concessão
 * "password grant" que foi implementado nessa aplicação.*/
public class OAuth2PasswordGrantAuthenticationTokenModelDeserializer extends JsonDeserializer<OAuth2PasswordGrantAuthenticationTokenModel> {

    @Override
    public OAuth2PasswordGrantAuthenticationTokenModel deserialize(JsonParser parser, DeserializationContext ctxt)
        throws IOException {
        ObjectMapper mapper = (ObjectMapper) parser.getCodec();
        JsonNode root = mapper.readTree(parser);

        String username = JsonNodeUtils.findStringValue(root, "username");
        String password = JsonNodeUtils.findStringValue(root, "password");
        String clientId = JsonNodeUtils.findStringValue(root, "clientId");

        Set<String> scopes = JsonNodeUtils.findValue(root, "scopes", JsonNodeUtils.STRING_SET, mapper);
        Collection<GrantedAuthority> authorities = JsonNodeUtils.findValue(root, "authorities", JsonNodeUtils.GRANTED_AUTHORITY_COLLECTION, mapper);
        Authentication clientPrincipal = new UsernamePasswordAuthenticationToken(clientId, null);

        return new OAuth2PasswordGrantAuthenticationTokenModel(username, password, clientPrincipal, scopes, authorities);
    }

    abstract class JsonNodeUtils {

        static final TypeReference<Set<String>> STRING_SET = new TypeReference<Set<String>>() { };

        static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<Map<String, Object>>() {};

        static final TypeReference<Collection<GrantedAuthority>> GRANTED_AUTHORITY_COLLECTION = new TypeReference<Collection<GrantedAuthority>>() {};


        static String findStringValue(JsonNode jsonNode, String fieldName) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isTextual()) ? value.asText() : null;
        }

        static <T> T findValue(JsonNode jsonNode, String fieldName, TypeReference<T> valueTypeReference,
                               ObjectMapper mapper) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isContainerNode()) ? mapper.convertValue(value, valueTypeReference) : null;
        }

        static JsonNode findObjectNode(JsonNode jsonNode, String fieldName) {
            if (jsonNode == null) {
                return null;
            }
            JsonNode value = jsonNode.findValue(fieldName);
            return (value != null && value.isObject()) ? value : null;
        }

    }
}
