package com.beamedcallum.gateway.application.controller;

import com.beamedcallum.common.database.UserEntry;
import com.beamedcallum.common.database.UserRepository;
import com.beamedcallum.common.security.authorisation.GatewayTokenService;
import com.beamedcallum.common.security.model.AuthenticationRequest;
import com.beamedcallum.common.security.model.AuthenticationResponse;
import com.beamedcallum.gateway.authorization.refresh.RefreshTokenData;
import com.beamedcallum.gateway.authorization.refresh.RefreshTokenService;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTFactory;
import com.beamedcallum.gateway.authorization.tokens.jwt.JWTToken;
import com.beamedcallum.gateway.authorization.tokens.jwt.exceptions.JWTParseException;
import com.beamedcallum.gateway.tokens.exceptions.TokenExpiredException;
import com.beamedcallum.gateway.tokens.exceptions.TokenIntegrityException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import common.discovery.DiscoveryUtils;
import common.discovery.messages.ServiceFoundResponse;
import common.exception.RestErrorObject;
import common.exception.RestRuntimeException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

@RestController
public class GatewayController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    GatewayTokenService gatewayTokenService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String homepage() {
        return "Welcome";
    }

    @PostMapping("/api/login")
    public AuthenticationResponse login(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new RestRuntimeException("Bad Credentials", HttpStatus.FORBIDDEN);
        }

        UserEntry user = userRepository.findById(authenticationRequest.getUsername()).get();

        RefreshTokenData<JWTToken, JWTToken> tokens = gatewayTokenService.create();
        gatewayTokenService.authoriseToken(user.getUsername(), user.getRoles(), tokens.getRefreshToken(), tokens.getAuthToken());

        return new AuthenticationResponse<>(tokens.getRefreshToken().get(), tokens.getAuthToken().get());
    }

    @PostMapping("/api/refresh")
    public AuthenticationResponse refresh(HttpServletRequest request) throws JWTParseException, TokenIntegrityException, TokenExpiredException {
        JWTToken token = JWTFactory.getInstance().parseFromString(request.getHeader("Refresh"));

        boolean isValid = gatewayTokenService.isRefreshValid(token);

        if (isValid) {
            System.out.println("[Debug] Generating new Tokens!");
            RefreshTokenData<JWTToken, JWTToken> data = gatewayTokenService.generateChildAuth(token);
            return new AuthenticationResponse<>(data.getRefreshToken().get(), data.getAuthToken().get());
        } else {
            if (!gatewayTokenService.isCurrentGeneration(token, RefreshTokenService.TOKEN_TYPE.REFRESH_TOKEN)) {
                gatewayTokenService.invalidateToken(token);
                throw new RestRuntimeException("Expired Credentials", HttpStatus.FORBIDDEN);
            }
        }

        throw new RestRuntimeException("Bad Credentials", HttpStatus.UNAUTHORIZED);
    }

    @GetMapping("/api/authtest")
    public String test() {
        return "Authenticated";
    }

    @PostMapping("/api/register")
    public AuthenticationResponse register(@RequestBody AuthenticationRequest request) {
        Optional<UserEntry> user = userRepository.findById(request.getUsername());
        user.ifPresentOrElse(userEntry -> {
            throw new RestRuntimeException("User already Exists!", HttpStatus.CONFLICT);
        }, () -> {
            UserEntry userEntry = new UserEntry(request.getUsername(), passwordEncoder.encode(request.getPassword()), true);
            userRepository.save(userEntry);
        });

        return login(request);
    }

    @GetMapping("/api/{service}/**")
    public ResponseEntity<?> getService(HttpServletRequest request, @PathVariable String service) {
        //TODO: Dynamic Mapping / Read value from file.
        String location = "localhost:8082";
        ServiceFoundResponse serviceData = DiscoveryUtils.getServiceData(service, location);

        try {
            JWTToken token = JWTFactory.getInstance().parseFromString(request.getHeader("Authorisation"));

            if (!hasRole(token, serviceData.getDefaultRole())) {
                throw new RestRuntimeException("You do not have the required role!", HttpStatus.FORBIDDEN);
            }

            RestTemplate restTemplate = new RestTemplate();
            String serviceUrl = rewriteUrl(request, serviceData);
            return restTemplate.getForObject(serviceUrl, ResponseEntity.class);

        } catch (JWTParseException | TokenIntegrityException e) {
            throw new RestRuntimeException("Unexpected Error", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (HttpClientErrorException e) {
            throw new RestRuntimeException("This page does not exist", HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping("/api/{service}/**")
    public ResponseEntity<?> getServicePost(HttpServletRequest request, @PathVariable String service, @RequestBody String body) throws JsonProcessingException {
        //TODO: Dynamic Mapping / Read value from file.
        String location = "localhost:8082";
        ServiceFoundResponse serviceData = DiscoveryUtils.getServiceData(service, location);

        try {
            JWTToken token = JWTFactory.getInstance().parseFromString(request.getHeader("Authorisation"));

            if (!hasRole(token, serviceData.getDefaultRole())) {
                throw new RestRuntimeException("You do not have the required role!", HttpStatus.FORBIDDEN);
            }

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

            String serviceUrl = rewriteUrl(request, serviceData);

            return restTemplate.postForObject(serviceUrl, requestEntity, ResponseEntity.class);
        } catch (HttpClientErrorException e) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(e.getResponseBodyAsString()).get("error");

            RestErrorObject err = objectMapper.treeToValue(rootNode, RestErrorObject.class);

            throw new RestRuntimeException(err);
        } catch (JWTParseException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenParsing", HttpStatus.BAD_REQUEST);
        } catch (TokenIntegrityException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenIntegrity", HttpStatus.BAD_REQUEST);
        }
    }

    @PutMapping("/api/{service}/**")
    public ResponseEntity<?> getServicePut(HttpServletRequest request, @PathVariable String service, @RequestBody String body) throws JsonProcessingException {
        //TODO: Dynamic Mapping / Read value from file.
        String location = "localhost:8082";
        ServiceFoundResponse serviceData = DiscoveryUtils.getServiceData(service, location);

        try {
            JWTToken token = JWTFactory.getInstance().parseFromString(request.getHeader("Authorisation"));

            if (!hasRole(token, serviceData.getDefaultRole())) {
                throw new RestRuntimeException("You do not have the required role!", HttpStatus.FORBIDDEN);
            }

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

            String serviceUrl = rewriteUrl(request, serviceData);

            return restTemplate.exchange(serviceUrl, HttpMethod.PUT, requestEntity, ResponseEntity.class);
        } catch (HttpClientErrorException e) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(e.getResponseBodyAsString()).get("error");

            RestErrorObject err = objectMapper.treeToValue(rootNode, RestErrorObject.class);

            throw new RestRuntimeException(err);
        } catch (JWTParseException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenParsing", HttpStatus.BAD_REQUEST);
        } catch (TokenIntegrityException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenIntegrity", HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/api/{service}/**")
    public ResponseEntity<?> getServiceDelete(HttpServletRequest request, @PathVariable String service, @RequestBody String body) throws JsonProcessingException {
        //TODO: Dynamic Mapping / Read value from file.
        String location = "localhost:8082";
        ServiceFoundResponse serviceData = DiscoveryUtils.getServiceData(service, location);

        try {
            JWTToken token = JWTFactory.getInstance().parseFromString(request.getHeader("Authorisation"));

            if (!hasRole(token, serviceData.getDefaultRole())) {
                throw new RestRuntimeException("You do not have the required role!", HttpStatus.FORBIDDEN);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

            String serviceUrl = rewriteUrl(request, serviceData);

            RestTemplate restTemplate = new RestTemplate();
            return restTemplate.exchange(serviceUrl, HttpMethod.DELETE, requestEntity, ResponseEntity.class);
        } catch (HttpClientErrorException e) {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(e.getResponseBodyAsString()).get("error");

            RestErrorObject err = objectMapper.treeToValue(rootNode, RestErrorObject.class);

            throw new RestRuntimeException(err);
        } catch (JWTParseException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenParsing", HttpStatus.BAD_REQUEST);
        } catch (TokenIntegrityException e) {
            throw new RestRuntimeException(e.getMessage(), "tokenIntegrity", HttpStatus.BAD_REQUEST);
        }
    }

    private boolean hasRole(JWTToken user, String role) {
        //TODO: Role Hierarchy
        List<String> roleData = Arrays.asList(user.getClaim("roles").trim().split(","));
        return roleData.contains(role);
    }

    private String rewriteUrl(HttpServletRequest request, ServiceFoundResponse serviceData) {
        String hostname = serviceData.getHostname();

        List<String> url = new LinkedList<>(Arrays.asList(request.getRequestURL().toString().replace("//", "/").split("/")));
        String protocol = url.get(0);
        url.remove(3); //Removes Service
        url.remove(2); //Removes Gateway
        url.remove(1); //Removes Host + Port
        url.remove(0); //Removes Protocol

        StringBuilder newUrl = new StringBuilder();

        for (String s : url) {
            newUrl.append("/").append(s);
        }

        return protocol + "//" + hostname + newUrl;
    }
}
