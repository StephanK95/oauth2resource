package com.klamann.oauth2resource.accessToken;

import com.google.common.io.CharStreams;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class AccessTokenVerifier extends OncePerRequestFilter {

    private static final String AUTHORIZATIONHEADERNAMES[] = {"Authorization", "authorization"};

    private static final String TOKENPREFIX = "Bearer";

    private static final String home = System.getProperty("user.home");

    private AccessTokenEntry accessTokenEntry;

    @Autowired
    public AccessTokenVerifier(AccessTokenEntry accessToken) {
        this.accessTokenEntry = accessToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        long authSetCounter = 0;
        String accessToken = "";

        Optional<String> authTokenWithBearerFromHeader = getAuthorizationHeader(request);

        Optional<String> authTokenWithBearerFromBody = getAuthorizationBody(request);
        Optional<String> authTokenWithBearerFromQuery = getAuthorizationQuery(request);

        if ((authTokenWithBearerFromHeader.isEmpty() || !authTokenWithBearerFromHeader.get().split(" ")[0].equalsIgnoreCase(TOKENPREFIX))
        && authTokenWithBearerFromBody.isEmpty()
        && authTokenWithBearerFromQuery.isEmpty()) {

            tokenMissingResponseCreation("\"message\": \"Token or Bearer prefix missing\", \n", request, response);
            return;
        }

        if (authTokenWithBearerFromHeader.isPresent()) {
            accessToken = authTokenWithBearerFromHeader.get().replaceAll("(?i)" + TOKENPREFIX, "").strip();
            authSetCounter++;
        }
        if (authTokenWithBearerFromBody.isPresent()) {
            if (authSetCounter > 0) {
                tooManyAccessTokenFailure(request, response);
                return;
            }
            accessToken = authTokenWithBearerFromBody.get();
        }
        if (authTokenWithBearerFromQuery.isPresent()) {
            if (authSetCounter > 0) {
                tooManyAccessTokenFailure(request, response);
                return;
            }
            accessToken = authTokenWithBearerFromQuery.get();
        }

        if (accessToken.equals("null")) {
            tokenMissingResponseCreation("\"message\": \"Token or Bearer prefix missing\", \n", request, response);
            return;
        }

        String token = accessToken;


        List<String> lines = Files.readAllLines(Path.of( home + File.separator + "Documents" + File.separator + "GitHub" + File.separator + "ouath2authorizationserver" + File.separator + "accessTokens.txt"));

        List<AccessTokenEntry> accessTokenEntries = lines.stream().map(s -> {
            String[] splittedString = s.split(" ");
            List<String> scopeList = new ArrayList<>();
            for (int i = 3; i < splittedString.length; i++) {
                scopeList.add(splittedString[i]);
            }
            return new AccessTokenEntry(splittedString[0], splittedString[1], splittedString[2], scopeList);
        }).collect(Collectors.toList());

        Optional<AccessTokenEntry> first = accessTokenEntries.stream().filter(accessTokenEntry -> accessTokenEntry.getAccessToken().equals(token)).findFirst();

        if (first.isEmpty()) {
            tokenMissingResponseCreation(String.format("\"message\": \"Token: %s not found\", \n", accessToken), request, response);
            return;
        }

        accessTokenEntry.setAccessToken(first.get().getAccessToken());
        accessTokenEntry.setScope(first.get().getScope());
        accessTokenEntry.setClientId(first.get().getClientId());

        filterChain.doFilter(request, response);

    }

    private void tokenMissingResponseCreation(String str, HttpServletRequest request, HttpServletResponse response) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("\"error\": \"Unauthorized\", \n");
        sb.append(str);
        sb.append("\"path\": \"")
                .append(request.getRequestURL())
                .append("\"");
        sb.append("} ");

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(sb.toString());
        response.setStatus(403);
    }

    private void tooManyAccessTokenFailure(HttpServletRequest request, HttpServletResponse response) throws IOException {
        tokenMissingResponseCreation("\"message\": \"Too many access tokens\", \n", request, response);
    }

    private Optional<String> getAuthorizationQuery(HttpServletRequest request) {
        Iterator<String> parameterIterator = request.getParameterNames().asIterator();
        while (parameterIterator.hasNext()) {
            String next = parameterIterator.next();
            if (next.equals("access_token")) {
                return Optional.of(request.getParameter(next));
            }
        }
        return Optional.empty();
    }

    private Optional<String> getAuthorizationBody(HttpServletRequest request) throws IOException {
        String body = CharStreams.toString(request.getReader());
        if (!body.contains("access_token")) {
            return Optional.empty();
        }
        String[] splitted = body.split("=");
        for (int i = 0; i < splitted.length; i++) {
            if (splitted[i].contains("access_token")) {
                return Optional.of(splitted[i+1]);
            }
        }

        return Optional.empty();
    }

    private Optional<String> getAuthorizationHeader(HttpServletRequest request) {
        Iterator<String> headerIterator = request.getHeaderNames().asIterator();
        while(headerIterator.hasNext()) {
            String header = headerIterator.next();
            if (Arrays.asList(AUTHORIZATIONHEADERNAMES).contains(header)) {
                return Optional.of(request.getHeader(header));
            }
        }
        return Optional.empty();
    }
}


