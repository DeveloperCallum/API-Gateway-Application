package com.beamedcallum.common.rest;

import com.beamedcallum.database.accounts.models.Account;
import common.account.AccountBasicInfo;
import common.exception.RestErrorObject;
import common.exception.ServerException;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

public class RetrieveAccount {
    public String username;

    public RetrieveAccount(String username) {
        this.username = username;
    }

    public Account get() throws ServerException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<AccountBasicInfo> request = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Account> response = restTemplate.exchange("http://localhost:8083/users/" + username, HttpMethod.GET, request, Account.class);

        if (response.getStatusCode().value() == HttpStatus.OK.value()){
            return response.getBody();
        }

        throw new ServerException(new RestErrorObject("The server did not receive the expected response.", "Internal Server Error", response.getStatusCode()));
    }
}
