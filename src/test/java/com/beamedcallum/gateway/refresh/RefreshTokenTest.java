package com.beamedcallum.gateway.refresh;

import com.beamedcallum.common.security.authorisation.GatewayTokenService;
import com.beamedcallum.common.security.model.User;
import com.beamedcallum.gateway.authorization.refresh.RefreshTokenData;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTToken;
import com.beamedcallum.gateway.tokens.exceptions.TokenExpiredException;
import com.beamedcallum.gateway.tokens.exceptions.TokenRuntimeException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

public class RefreshTokenTest {
    private GatewayTokenService gatewayTokenService = new GatewayTokenService();
    User user = new User("test", "user", true);
    JWTToken auth;
    JWTToken refresh;

    @BeforeEach
    public void prepare(){
        RefreshTokenData<JWTToken, JWTToken> token = gatewayTokenService.create();

        JWTToken auth = token.getAuthToken();
        JWTToken refresh = token.getRefreshToken();

        this.auth = auth;
        this.refresh = refresh;
    }

    @Order(0)
    @Test
    public void authoriseTokens() {
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);

        Assertions.assertNotNull(auth.getClaim("id"));
        Assertions.assertNotNull(refresh.getClaim("id"));
        Assertions.assertEquals(auth.getClaim("id"), refresh.getClaim("id"));
    }

    @Order(1)
    @Test
    public void validateAuthToken() {
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);
        Assertions.assertTrue(gatewayTokenService.isAuthValid(auth));
    }

    @Order(2)
    @Test
    public void validateRefreshToken() {
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);
        Assertions.assertTrue(gatewayTokenService.isRefreshValid(refresh));
    }

    @Order(3)
    @Test
    public void newGenerationTest(){
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);
        Assertions.assertTrue(gatewayTokenService.isRefreshValid(refresh));

        try {
            RefreshTokenData<JWTToken, JWTToken> data = gatewayTokenService.generateChildAuth(refresh);
            Assertions.assertTrue(gatewayTokenService.isAuthValid(data.getAuthToken()));
            Assertions.assertTrue(gatewayTokenService.isRefreshValid(data.getRefreshToken()));
        } catch (TokenExpiredException e) {
            e.printStackTrace();
        }
    }

    @Order(4)
    @Test
    public void oldGenerationTest(){
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);
        Assertions.assertTrue(gatewayTokenService.isRefreshValid(refresh));

        try {
            RefreshTokenData<JWTToken, JWTToken> data = gatewayTokenService.generateChildAuth(refresh);
            Assertions.assertFalse(gatewayTokenService.isAuthValid(auth));
            Assertions.assertFalse(gatewayTokenService.isRefreshValid(refresh));
        } catch (TokenExpiredException e) {
            e.printStackTrace();
        }
    }

    @Order(5)
    @Test
    public void invalidate(){
        gatewayTokenService.authoriseToken(user.getUsername(), refresh, auth);
        Assertions.assertTrue(gatewayTokenService.isRefreshValid(refresh));

        gatewayTokenService.invalidateToken(auth);
        Assertions.assertThrows(TokenRuntimeException.class, () -> gatewayTokenService.isRefreshValid(refresh));
    }
}
