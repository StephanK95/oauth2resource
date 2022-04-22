package com.klamann.oauth2resource.scope;

import com.klamann.oauth2resource.accessToken.AccessTokenEntry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class ScopeVerifier extends OncePerRequestFilter {

    AccessTokenEntry accessTokenEntry;

    private final Map<String, String> scopeMap = Map.of("GET", "get", "PUT", "put", "POST", "post", "DELETE", "delete");

    @Autowired
    public ScopeVerifier(AccessTokenEntry accessTokenEntry) {
        this.accessTokenEntry = accessTokenEntry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        Optional<String> scopeOptional = accessTokenEntry.getScope().stream().filter(scope -> scope.equalsIgnoreCase(scopeMap.get(request.getMethod()))).findFirst();

        if (scopeOptional.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("{ ");
            sb.append("\"error\": \"Unauthorized\", \n");
            sb.append("\"message\": \"Scope: " + accessTokenEntry.getScope() + " does not allow to access " + request.getRequestURI()  + " with HTTP-Method " + request.getMethod() + "\", \n");
            sb.append("\"path\": \"")
                    .append(request.getRequestURL())
                    .append("\"");
            sb.append("} ");

            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(sb.toString());
            response.setStatus(401);
        }

        filterChain.doFilter(request, response);

    }
}
