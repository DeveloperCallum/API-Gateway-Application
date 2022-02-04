package com.beamedcallum.common.security.authorisation;

import common.exception.RestRuntimeException;
import com.beamedcallum.gateway.authorization.refresh.RefreshTokenData;
import com.beamedcallum.gateway.authorization.refresh.RefreshTokenService;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTFactory;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTToken;
import com.beamedcallum.gateway.authorization.tokens.jwt.exceptions.JWTParseException;
import com.beamedcallum.gateway.tokens.SelfContainedToken;
import com.beamedcallum.gateway.tokens.exceptions.TokenExpiredException;
import com.beamedcallum.gateway.tokens.exceptions.TokenIntegrityException;
import com.beamedcallum.gateway.tokens.exceptions.TokenRuntimeException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.temporal.ChronoUnit;

@Service
public class GatewayTokenService extends RefreshTokenService<JWTToken, JWTToken> {

    @Deprecated
    public void authoriseToken(String username, JWTToken refreshToken, JWTToken authToken) {
        authoriseToken(new GatewayRunnable(username, refreshToken, authToken, false));
    }

    public void authoriseToken(String username, String roleCSV, JWTToken refreshToken, JWTToken authToken) {
        authoriseToken(new GatewayRunnable(username, roleCSV, refreshToken, authToken, false));
    }

    public void authoriseToken(int id, String username, JWTToken refreshToken, JWTToken authToken) {
        authoriseToken(new GatewayRunnable(id, username, refreshToken, authToken, false));
    }

    @Override
    protected JWTToken generateAuthToken() {
        JWTToken authToken = JWTFactory.getInstance().createDefault(10, ChronoUnit.MINUTES);
//        authToken.addClaim("authorisationToken", UUID.randomUUID().toString());

        return authToken;
    }

    @Override
    protected JWTToken generateRefreshToken() {
        JWTToken authToken = JWTFactory.getInstance().createDefault(30, ChronoUnit.MINUTES);
//        authToken.addClaim("refreshToken", UUID.randomUUID().toString());

        return authToken;
    }

    /**
     * create a new generation of tokens
     *
     * @param refreshToken The token that was given for refreshing
     * @return The new tokens
     * @throws TokenExpiredException
     */
    @Override
    public RefreshTokenData<JWTToken, JWTToken> generateChildAuth(JWTToken refreshToken) throws TokenExpiredException {
        if (isRefreshValid(refreshToken)) {
            //Do this
            try {
                int id = Integer.parseInt(refreshToken.getClaim("id"));
                boolean currentGen = isCurrentGeneration(id, refreshToken, TOKEN_TYPE.REFRESH_TOKEN);

                if (!currentGen) {
                    throw new TokenExpiredException("Token is an older generation");
                }

                JWTToken auth = generateAuthToken();
                JWTToken refresh = generateRefreshToken();

                GatewayRunnable gatewayRunnable = new GatewayRunnable(id, refreshToken.getClaim("username"), refresh, auth, true);
                gatewayRunnable.authoriseToken();

                return gatewayRunnable.getData();
            } catch (NumberFormatException e) {
                throw new TokenRuntimeException("Failed to get token ID");
            }
        } else {
            throw new TokenRuntimeException("Failed to generate token, token wasn't valid.");
        }
    }

    private boolean basicTokenChecks(SelfContainedToken<?> token) throws TokenIntegrityException {
        boolean isValid = false;
        try {
            isValid = JWTFactory.getInstance().isValid(token.get());
        } catch (JWTParseException e) {
            throw new TokenIntegrityException("Malformed Token");
        }

        if (!isValid) {
            throw new TokenIntegrityException("Token was invalid");
        }

        if (token.isExpired()) {
            return false;
        }

        return true;
    }

    @Override
    public boolean isAuthValid(JWTToken auth) {
        try {
            if (!basicTokenChecks(auth)) {
                return false;
            }
        } catch (TokenIntegrityException e) {
            return false;
        }

        int id;
        try {
            id = Integer.parseInt(auth.getClaim("id"));
        } catch (NumberFormatException e) {
            return false;
        }

        if (!tokenExists(id, auth, TOKEN_TYPE.AUTHORISATION_TOKEN)) {
            return false;
        }

        boolean currentGen = isCurrentGeneration(id, auth, TOKEN_TYPE.AUTHORISATION_TOKEN);

        if (!currentGen) {
            return false;
        }

        return true;
    }

    @Override
    public boolean isRefreshValid(JWTToken refresh) {
        try {
            if (!basicTokenChecks(refresh)) {
                return false;
            }

            int id;
            try {
                id = Integer.parseInt(refresh.getClaim("id"));
            } catch (NumberFormatException e) {
                return false;
            }

            boolean currentGen = isCurrentGeneration(id, refresh, TOKEN_TYPE.REFRESH_TOKEN);

            if (!currentGen) {
                return false;
            }

            if (!tokenExists(id, refresh, TOKEN_TYPE.REFRESH_TOKEN)) {
                return false;
            }
        } catch (TokenIntegrityException e) {
            return false;
        }

        return true;
    }

    @Override
    public void invalidateToken(SelfContainedToken<?> token) {
        try {
            int id = Integer.parseInt(token.getClaim("id"));
            super.invalidateToken(new GatewayRunnable(id));
        } catch (NumberFormatException e) {
            throw new RestRuntimeException("", HttpStatus.BAD_REQUEST);
        }
    }

    private class GatewayRunnable extends RefreshRunnable {
        private String username;
        private String roleCSV;

        private boolean isChild;

        public GatewayRunnable(int id, String username, String roleCSV, JWTToken refreshToken, JWTToken authToken, boolean isChild) {
            super(id, refreshToken, authToken);
            this.username = username;
            this.roleCSV = roleCSV;
            this.isChild = isChild;
        }

        public GatewayRunnable(String username, String roleCSV, JWTToken refreshToken, JWTToken authToken, boolean isChild) {
            super(refreshToken, authToken);
            this.username = username;
            this.roleCSV = roleCSV;
            this.isChild = isChild;
        }

        @Deprecated
        public GatewayRunnable(int id, String username, JWTToken refreshToken, JWTToken authToken, boolean isChild) {
            super(id, refreshToken, authToken);
            this.username = username;
            this.isChild = isChild;
        }

        @Deprecated
        public GatewayRunnable(String username, JWTToken refreshToken, JWTToken authToken, boolean isChild) {
            super(refreshToken, authToken);
            this.username = username;
            this.isChild = isChild;
        }

        public GatewayRunnable(int id) {
            super(id);
        }

        @Override
        public void authoriseToken() {
            if (!isChild) {
                if (!containsKey(getId())) {
                    setId(generateID());
                }

                setupTokens();
                setData(add(getId(), getRefreshToken(), getAuthToken()));
                return;
            }

            setupTokens();
            setData(addChild(getId(), getRefreshToken(), getAuthToken()));
        }

        @Override
        public void invalidateToken() {
            super.invalidateToken();
        }

        private void setupTokens() {
            getAuthToken().addClaim("id", String.valueOf(getId()));
            getRefreshToken().addClaim("id", String.valueOf(getId()));

            getAuthToken().addClaim("username", getUsername());
            getRefreshToken().addClaim("username", getUsername());

            getAuthToken().addClaim("roles", roleCSV);

            getAuthToken().regenerate();
            getRefreshToken().regenerate();
        }

        public String getUsername() {
            return username;
        }

        @Override
        public RefreshTokenData<JWTToken, JWTToken> getData() {
            return super.getData();
        }
    }
}
