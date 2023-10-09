package com.myapps.springbootsecurity.config;

import com.myapps.springbootsecurity.filter.JwtTokenFilter;
import com.myapps.springbootsecurity.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter{
	private final CustomUserDetailsService userDetailsService;

	private final JwtTokenFilter jwtTokenFilter;

	public SpringSecurityConfiguration(CustomUserDetailsService userDetailsService,
									   JwtTokenFilter jwtTokenFilter) {
		this.userDetailsService = userDetailsService;
		this.jwtTokenFilter = jwtTokenFilter;
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(username -> userDetailsService
				.loadUserByUsername(username)
//				.orElseThrow(
//						() -> new UsernameNotFoundException(
//								format("User: %s, not found", username)
//						)
//				)
		);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		// Enable CORS and disable CSRF
		http = http.cors().and().csrf().disable();

		// Set session management to stateless
		http = http
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and();

		// Set unauthorized requests exception handler
		http = http
				.exceptionHandling()
				.authenticationEntryPoint(
						(request, response, ex) -> {
							response.sendError(
									HttpServletResponse.SC_UNAUTHORIZED,
									ex.getMessage()
							);
						}
				)
				.and();

		// Set permissions on endpoints
		http.authorizeRequests()
				// Public endpoints
				.antMatchers("/api/login").permitAll()
//				.antMatchers(HttpMethod.GET, "/api/author/**").permitAll()
//				.antMatchers(HttpMethod.POST, "/api/author/search").permitAll()
				// Private endpoints
				.antMatchers("/api/admin/**").hasRole("ADMIN")
				.antMatchers("/api/user/**").hasRole("USER")
				.anyRequest().authenticated();

		// Add JWT token filter
		http.addFilterBefore(
				jwtTokenFilter,
				UsernamePasswordAuthenticationFilter.class
		);

	}

	// Used by Spring Security if CORS is enabled.
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source =
				new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		source.registerCorsConfiguration("/**", config);
		return new CorsFilter(source);
	}

	@Override @Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	GrantedAuthorityDefaults grantedAuthorityDefaults() {
		return new GrantedAuthorityDefaults(""); // Remove the ROLE_ prefix
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}


}
