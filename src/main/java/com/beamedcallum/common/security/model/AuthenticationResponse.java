package com.beamedcallum.common.security.model;

public class AuthenticationResponse<K, V> {
    private K refreshToken;
    private V authToken;

    public AuthenticationResponse(K refresh, V auth) {
        this.refreshToken = refresh;
        this.authToken = auth;
    }

    public K getRefreshToken() {
        return refreshToken;
    }

    public V getAuthToken() {
        return authToken;
    }
}