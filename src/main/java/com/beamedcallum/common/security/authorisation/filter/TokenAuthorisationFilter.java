package com.beamedcallum.common.security.authorisation.filter;

import com.beamedcallum.common.database.UserRepository;
import com.beamedcallum.common.security.authorisation.GatewayTokenService;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTFactory;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTToken;
import com.beamedcallum.gateway.authorization.tokens.jwt.exceptions.JWTParseException;
import com.beamedcallum.gateway.tokens.exceptions.TokenIntegrityException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class TokenAuthorisationFilter extends OncePerRequestFilter {
    GatewayTokenService gatewayTokenService;

    public TokenAuthorisationFilter(GatewayTokenService gatewayTokenService) {
        this.gatewayTokenService = gatewayTokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorisation = request.getHeader("Authorisation");

        if (authorisation != null) {
            try {

                JWTToken auth = JWTFactory.getInstance().parseFromString(authorisation);

                if (auth != null) {
                    String username = auth.getClaim("username");

                    boolean valid = gatewayTokenService.isAuthValid(auth);

                    if (valid) {
                        SecurityContextHolder.getContext().setAuthentication(
                                new PreAuthenticatedAuthenticationToken(
                                        username,
                                        auth.get(),
                                        AuthorityUtils.commaSeparatedStringToAuthorityList(auth.getClaim("roles").trim())));
                    } else {
                        gatewayTokenService.invalidateToken(auth);
                        System.out.println("[Debug]: Invalidated all tokens!");
                    }
                }

            } catch (JWTParseException | TokenIntegrityException ignored) {
            } finally {
                filterChain.doFilter(request, response);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
