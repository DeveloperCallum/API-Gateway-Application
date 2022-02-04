package com.beamedcallum.common.security.authorisation.filter;

import com.beamedcallum.common.security.model.User;
import com.beamedcallum.gateway.authorization.tokens.uuid.UUIDAuthorisationService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@Component
public class UUIDAuthorisationFilter extends OncePerRequestFilter {

    private UUIDAuthorisationService<User> authService;

    public UUIDAuthorisationFilter(UUIDAuthorisationService authService) {
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String uuidRaw = request.getHeader("Authorisation");

        if (uuidRaw != null){
            System.out.println(uuidRaw);
            try{
                UUID uuid = UUID.fromString(uuidRaw);
                User user = authService.getUser(uuid);

                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities()));
            }catch (Exception e){
            }
        }

        filterChain.doFilter(request,response);
    }
}
