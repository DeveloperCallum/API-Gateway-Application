package com.beamedcallum.common.rest;

import common.account.AccountBasicInfo;
import common.exception.ServerException;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

public class ValidateAccount {
    private String username;
    private String password;
    private boolean wasProcessed = false;
    private boolean isValid = false;

    public ValidateAccount(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public boolean isCorrect() throws ServerException {

        if (wasProcessed){
            return isValid;
        }

        boolean check = checkPassword();

        wasProcessed = true;
        isValid = check;

        return check;
    }

    private boolean checkPassword() throws ServerException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        AccountBasicInfo basicInfo = new AccountBasicInfo(username, password);

        HttpEntity<AccountBasicInfo> request = new HttpEntity<>(basicInfo, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange("http://localhost:8083/user/validate", HttpMethod.POST, request, String.class);
        HttpStatus code = response.getStatusCode();

        if (code.value() == HttpStatus.FORBIDDEN.value()){
            return false;
        }

        if (code.value() == HttpStatus.OK.value()){
            return true;
        }

        throw new ServerException(response.getBody(), response.getStatusCode());
    }
}
