package com.microsoft.auth;

import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.auth.AuthContext;
import java.net.MalformedURLException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Tests {

	public static void main(final String[] args) {
		final Tests test = new Tests();
		try {
			test.getOneToken();
		} catch (final MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void getOneToken() throws MalformedURLException {
		final String authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
		final String resource = "https://graph.microsoft.com";
		final ExecutorService service = Executors.newFixedThreadPool(1);

		final AuthContext context = new AuthContext(authURL, false, service);
		final AuthenticationResult result = context.acquireToken(resource, "926e099c-ee16-4190-af72-dd5a45539674", // client_id
				"G5ndA196btI7DrkR8BwruOgO7aYU3di0vgk9tUPFraE=", // secret
				"test.user.1@kitscead.onmicrosoft.com", // login
				"2019@Tuhin#$", // password
				null);

		System.out.println("Access Token - " + result.getAccessToken());
		System.out.println("Refresh Token - " + result.getRefreshToken());
		System.out.println("ID Token - " + result.getIdToken());
		System.out.println("User Info - " + result.getUserInfo().getGivenName());
		service.shutdown();
	}

	public void getTokenHandler() throws MalformedURLException, ExecutionException, InterruptedException {
		final AuthContext context = new AuthContext("926e099c-ee16-4190-af72-dd5a45539674", // client_id
				"G5ndA196btI7DrkR8BwruOgO7aYU3di0vgk9tUPFraE=", // secret
				"test.user.1@kitscead.onmicrosoft.com", // login
				"2019@Tuhin#$", // password
				null);
		AuthenticationResult result = context.acquireToken();
		System.out.println("Access Token - " + result.getAccessToken());
		System.out.println("Refresh Token - " + result.getRefreshToken());
		System.out.println("ID Token - " + result.getIdToken());

		result = context.refreshToken();
		System.out.println("Access Token - " + result.getAccessToken());
		System.out.println("Refresh Token - " + result.getRefreshToken());
		System.out.println("ID Token - " + result.getIdToken());
		context.shutdownService();
	}
}
