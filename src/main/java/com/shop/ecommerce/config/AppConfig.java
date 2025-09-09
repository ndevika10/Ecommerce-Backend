package com.shop.ecommerce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
public class AppConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // ✅ Make session stateless
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // ✅ Enable CORS with allowed origins (Frontend & Backend)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration cfg = new CorsConfiguration();

                    cfg.setAllowedOrigins(Arrays.asList(
                            "http://localhost:3000",
                            "http://localhost:5173",
                            "http://localhost:4200",
                            "https://devikas-shop.vercel.app"
                            // ❌ Do NOT add backend URL here — backend doesn’t call itself through CORS
                    ));

                    cfg.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                    cfg.setAllowCredentials(true); // Allow cookies/authorization headers
                    cfg.setAllowedHeaders(Arrays.asList(
                            "Authorization",
                            "Content-Type",
                            "X-Requested-With",
                            "Accept",
                            "Origin"
                    ));
                    cfg.setExposedHeaders(List.of("Authorization")); // if token is in header
                    cfg.setMaxAge(3600L);

                    return cfg;
                }))

                // ✅ Disable CSRF (not needed for stateless REST APIs)
                .csrf(csrf -> csrf.disable())

                // ✅ Configure authorization
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()    // Sign-in/sign-up allowed
                        .requestMatchers("/api/**").authenticated() // API needs authentication
                        .anyRequest().permitAll()
                )

                // ✅ Add JWT validator before BasicAuthenticationFilter
                .addFilterBefore(new JwtValidator(), BasicAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
