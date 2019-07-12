package com.microsoft.auth;

import com.microsoft.aad.adal4j.AdalAuthorizationGrant;
import com.microsoft.aad.adal4j.AuthenticationCallback;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;


public class AuthContext {
    private static String AUTHORITY = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    private static String RESOURCE = "https://graph.microsoft.com";
    private AuthenticationContext authenticationContext;
    private AuthenticationResult token;
    private long tokenCreatedTime;
    private String resource;
    private String clientId;
    private String clientSecret;
    private String username;
    private Secret password;
    private AuthenticationCallback callback;
    private ExecutorService service;

    public AuthContext(String authority, boolean validateAuthority, ExecutorService service) throws MalformedURLException {
        authenticationContext = new AuthenticationContext(authority, validateAuthority, service);
        this.service = service;
        token = null;
    }

    public AuthContext(String clientId, String clientSecret, String username, String password, AuthenticationCallback callback) throws MalformedURLException {
        this(AUTHORITY, false, Executors.newFixedThreadPool(1));
        this.resource = RESOURCE;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.username = username;
        this.password = new Secret(password);
        this.callback = callback;
    }

    public AuthenticationResult acquireToken(String resource, String clientId, String clientSecret, String username, String password, AuthenticationCallback callback) {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("resource", resource);
            params.put("client_secret", clientSecret);

            Class<?> adalOAuthAuthorizationGrant = Class.forName("com.microsoft.aad.adal4j.AdalOAuthAuthorizationGrant");
            Constructor<?> adalConstructor = adalOAuthAuthorizationGrant.getDeclaredConstructor(AuthorizationGrant.class, Map.class);
            adalConstructor.setAccessible(true);

            Class<?> clientAuthenticationPost = Class.forName("com.microsoft.aad.adal4j.ClientAuthenticationPost");
            Constructor<?> clientConstructor = clientAuthenticationPost.getDeclaredConstructor(ClientAuthenticationMethod.class, ClientID.class);
            clientConstructor.setAccessible(true);

            Method method = AuthenticationContext.class.getDeclaredMethod("acquireToken", AdalAuthorizationGrant.class, ClientAuthentication.class, AuthenticationCallback.class);
            method.setAccessible(true);

            return ((Future<AuthenticationResult>) method.invoke(authenticationContext,
                    adalConstructor.newInstance(new ResourceOwnerPasswordCredentialsGrant(username, new Secret(password)), params),
                    clientConstructor.newInstance(ClientAuthenticationMethod.NONE, new ClientID(clientId)),
                    callback)).get();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | ClassNotFoundException | InstantiationException | InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AuthenticationResult acquireToken() {
        if (token == null) {
            token = acquireToken(resource, clientId, clientSecret, username, password.getValue(), callback);
            tokenCreatedTime = System.currentTimeMillis() / 1000;
        } else if (!isTokenAlive()) {
            token = refreshToken();
        }
        return token;
    }

    public AuthenticationResult refreshToken(String refreshToken, String clientId, String clientSecret, AuthenticationCallback callback) {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_secret", clientSecret);

            Class<?> adalOAuthAuthorizationGrant = Class.forName("com.microsoft.aad.adal4j.AdalOAuthAuthorizationGrant");
            Constructor<?> adalConstructor = adalOAuthAuthorizationGrant.getDeclaredConstructor(AuthorizationGrant.class, Map.class);
            adalConstructor.setAccessible(true);

            Class<?> clientAuthenticationPost = Class.forName("com.microsoft.aad.adal4j.ClientAuthenticationPost");
            Constructor<?> clientConstructor = clientAuthenticationPost.getDeclaredConstructor(ClientAuthenticationMethod.class, ClientID.class);
            clientConstructor.setAccessible(true);

            Method method = AuthenticationContext.class.getDeclaredMethod("acquireToken", AdalAuthorizationGrant.class, ClientAuthentication.class, AuthenticationCallback.class);
            method.setAccessible(true);

            return ((Future<AuthenticationResult>) method.invoke(authenticationContext,
                    adalConstructor.newInstance(new RefreshTokenGrant(new RefreshToken(refreshToken)), params),
                    clientConstructor.newInstance(ClientAuthenticationMethod.NONE, new ClientID(clientId)),
                    callback)).get();
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | ClassNotFoundException | InstantiationException | InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AuthenticationResult refreshToken() {
        return token = refreshToken(token.getRefreshToken(), clientId, clientSecret, callback);
    }

    private boolean isTokenAlive() {
        return tokenCreatedTime + token.getExpiresAfter() > System.currentTimeMillis() / 1000;
    }

    //------------------------------------------------------------
    //----------------------    Service     ----------------------
    //------------------------------------------------------------

    public void shutdownService() {
        if (service != null && !service.isShutdown())
            service.shutdown();
    }

    public boolean isServiceShutdown() {
        return service.isShutdown();
    }

    public void newService() throws MalformedURLException {
        shutdownService();
        this.service = Executors.newFixedThreadPool(1);
        authenticationContext = new AuthenticationContext(AUTHORITY, false, service);
    }
}
