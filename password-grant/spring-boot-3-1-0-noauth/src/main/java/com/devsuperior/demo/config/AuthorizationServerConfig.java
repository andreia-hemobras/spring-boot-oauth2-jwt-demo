package com.devsuperior.demo.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;

import com.devsuperior.demo.config.customgrant.CustomPasswordAuthenticationConverter;
import com.devsuperior.demo.config.customgrant.CustomPasswordAuthenticationProvider;
import com.devsuperior.demo.config.customgrant.CustomUserAuthorities;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfig {

	@Value("${security.client-id}")
	private String clientId;

	@Value("${security.client-secret}")
	private String clientSecret;

	@Value("${security.jwt.duration}")
	private Integer jwtDurationSeconds;

	@Autowired
	private UserDetailsService userDetailsService;

	/*
	* Configura as regras de segurança do servidor OAuth2.
	* Define como o servidor vai processar requisições no endpoint /oauth2/token. Usa CustomPasswordAuthenticationConverter para transformar a requisição em um token de autenticação, e CustomPasswordAuthenticationProvider para validar as credenciais do usuário contra o banco de dados.
	* */
	@Bean
	@Order(2)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.tokenEndpoint(tokenEndpoint -> tokenEndpoint
				.accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
				.authenticationProvider(new CustomPasswordAuthenticationProvider(authorizationService(), tokenGenerator(), userDetailsService, passwordEncoder())));

		http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));

		return http.build();
	}

	/*
	* Armazena na memória os tokens emitidos.
	* Cada vez que um usuário faz login, um registro é criado aqui com informações do token. Em produção, você trocaria isso por um banco de dados.
	* */
	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	/*
	* Armazena consentimento do usuário.
	* Registra quando um usuário concorda em compartilhar seus dados com um cliente. É menos relevante no fluxo "password grant", mas está aqui por completude.
	* */
	@Bean
	public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	/*
	* Define como as senhas serão criptografadas.
	* Usa BCrypt, que é seguro e irreversível. Sempre que uma senha precisa ser validada, o sistema compara o hash em vez da senha em texto plano.
	* */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/*
	* Registra um cliente OAuth2 autorizado.
	* Define qual aplicação pode fazer login (client ID), sua senha secreta (client secret), e quais permissões ela tem (scopes: "read" e "write"). Sem esse registro, o cliente não consegue autenticar.
	* */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient
			.withId(UUID.randomUUID().toString())
			.clientId(clientId)
			.clientSecret(passwordEncoder().encode(clientSecret))
			.scope("read")
			.scope("write")
			.authorizationGrantType(new AuthorizationGrantType("password"))
			.tokenSettings(tokenSettings())
			.clientSettings(clientSettings())
			.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	/*
	* Define as configurações dos tokens.
	* Especifica que os tokens serão JWT auto-contidos (não precisa consultar banco para validar) e quanto tempo duram (exemplo: 1 hora).
	* */
	@Bean
	public TokenSettings tokenSettings() {

		return TokenSettings.builder()
			.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
			.accessTokenTimeToLive(Duration.ofSeconds(jwtDurationSeconds))
			.build();
	}

	/*
	* Configurações gerais do cliente.
	* Sem customizações aqui, usa configurações padrão do Spring Security
	* */
	@Bean
	public ClientSettings clientSettings() {
		return ClientSettings.builder().build();
	}

	/*
	* Configurações do servidor de autorização.
	* Define configurações globais como a URL do emissor (issuer) e endpoints. Também usa padrão do Spring.
	* */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}


	/*
	* Cria o gerador de tokens JWT.
	* Combina o gerador de JWT (que assina com a chave RSA privada) com o gerador de token de acesso. É aqui que os tokens são realmente criados.
	* */
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator);
	}

	/*
	 * Adiciona informações extras ao JWT.
	 * Pega os dados do usuário (nome, authorities/roles) e coloca dentro do token antes de assinar. Assim, qualquer serviço que receber o token já sabe quem é o usuário sem consultar o banco.
	 * */
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			OAuth2ClientAuthenticationToken principal = context.getPrincipal();
			CustomUserAuthorities user = (CustomUserAuthorities) principal.getDetails();
			List<String> authorities = user.getAuthorities().stream().map(x -> x.getAuthority()).toList();
			if (context.getTokenType().getValue().equals("access_token")) {
				context.getClaims()
					.claim("authorities", authorities)
					.claim("username", user.getUsername());
			}
		};
	}

	/*
	 * Cria o validador de JWTs.
	 * Quando uma requisição chega com um token, este decoder verifica se o token é válido, não expirou e foi realmente assinado por este servidor.
	 * */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/*
	 * Fornece as chaves públicas/privadas.
	 * Armazena a chave privada (usada para assinar tokens) e a chave pública (usada para validar tokens). Essas chaves são geradas através de generateRsa().
	 * */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	/*
	 * Gera as chaves RSA.
	 * Cria um par de chaves (pública e privada) de 2048 bits. A chave privada fica no servidor, a pública pode ser compartilhada.
	 * */
	private static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	/*
	 * Cria o algoritmo de geração de chaves.
	 * Usa o KeyPairGenerator do Java para gerar as chaves RSA com segurança. Se algum erro ocorrer, lança uma exceção.
	 * */
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}
