package com.beamedcallum.common.security.model;

import com.beamedcallum.common.database.UserEntry;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class User implements UserDetails {
    private String username;
    @JsonIgnore
    private String password;
    @JsonIgnore
    private boolean isActive;
    private Collection<? extends GrantedAuthority> Authorities;

    @JsonIgnore
    private boolean expiredPassword;

    public User(String username, String password, boolean isActive) {
        this.username = username;
        this.password = password;
        this.isActive = isActive;
    }

    public User(UserEntry userEntry) {
        this.username = userEntry.getUsername();
        this.password = userEntry.getPassword();
        this.isActive = userEntry.isEnabled();
        this.expiredPassword = userEntry.isPasswordExpired();
        this.Authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(userEntry.getRoles());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Authorities;
    }

    @Override @JsonIgnore
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return !expiredPassword;
    }

    @Override @JsonIgnore
    public boolean isEnabled() {
        return isActive;
    }
}
