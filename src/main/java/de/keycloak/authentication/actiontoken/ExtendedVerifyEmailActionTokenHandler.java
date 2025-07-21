package de.keycloak.authentication.actiontoken;

import com.google.auto.service.AutoService;
import de.keycloak.authentication.requiredaction.PeriodicVerifyEmail;
import de.keycloak.util.BuildDetails;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionToken;
import org.keycloak.authentication.actiontoken.verifyemail.VerifyEmailActionTokenHandler;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import java.util.stream.Stream;

@AutoService(ActionTokenHandlerFactory.class)
public class ExtendedVerifyEmailActionTokenHandler extends VerifyEmailActionTokenHandler implements ServerInfoAwareProviderFactory {

	@Override
	public Response handleToken(VerifyEmailActionToken token, ActionTokenContext<VerifyEmailActionToken> tokenContext) {
		UserModel user = tokenContext.getAuthenticationSession().getAuthenticatedUser();
		KeycloakSession session = tokenContext.getSession();
		AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
		EventBuilder event = tokenContext.getEvent();

		event.event(EventType.VERIFY_EMAIL).detail(Details.EMAIL, user.getEmail());

		if (user.isEmailVerified() && !isVerifyEmailActionSet(user, authSession)) {
			event.user(user).error(Errors.EMAIL_ALREADY_VERIFIED);
			return session.getProvider(LoginFormsProvider.class)
				.setAuthenticationSession(authSession)
				.setInfo(Messages.EMAIL_VERIFIED_ALREADY, user.getEmail())
				.setUser(user)
				.createInfoPage();
		}

		final UriInfo uriInfo = tokenContext.getUriInfo();
		final RealmModel realm = tokenContext.getRealm();

		if (tokenContext.isAuthenticationSessionFresh()) {
			// Update the authentication session in the token
			token.setCompoundOriginalAuthenticationSessionId(token.getCompoundAuthenticationSessionId());

			String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authSession).getEncodedId();
			token.setCompoundAuthenticationSessionId(authSessionEncodedId);
			UriBuilder builder = Urls.actionTokenBuilder(uriInfo.getBaseUri(), token.serialize(session, realm, uriInfo),
				authSession.getClient().getClientId(), authSession.getTabId(), AuthenticationProcessor.getClientData(session, authSession));
			String confirmUri = builder.build(realm.getName()).toString();

			return session.getProvider(LoginFormsProvider.class)
				.setAuthenticationSession(authSession)
				.setSuccess(Messages.CONFIRM_EMAIL_ADDRESS_VERIFICATION, user.getEmail())
				.setAttribute(Constants.TEMPLATE_ATTR_ACTION_URI, confirmUri)
				.setUser(user)
				.createInfoPage();
		}

		// verify user email as we know it is valid as this entry point would never have gotten here.
		user.setEmailVerified(true);
		user.setSingleAttribute(PeriodicVerifyEmail.EMAIL_VERIFIED_AT, String.valueOf(Time.currentTimeMillis()));
		user.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
		authSession.removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);

		String redirectUri = RedirectUtils.verifyRedirectUri(tokenContext.getSession(), token.getRedirectUri(), authSession.getClient());
		if (redirectUri != null) {
			authSession.setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
			authSession.setRedirectUri(redirectUri);
			authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
		}

		event.success();

		if (token.getCompoundOriginalAuthenticationSessionId() != null) {
			AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
			asm.removeAuthenticationSession(tokenContext.getRealm(), authSession, true);

			return session.getProvider(LoginFormsProvider.class)
				.setAuthenticationSession(authSession)
				.setSuccess(Messages.EMAIL_VERIFIED)
				.setUser(user)
				.createInfoPage();
		}

		tokenContext.setEvent(event.clone().removeDetail(Details.EMAIL).event(EventType.LOGIN));

		String nextAction = AuthenticationManager.nextRequiredAction(session, authSession, tokenContext.getRequest(), event);
		return AuthenticationManager.redirectToRequiredActions(session, realm, authSession, uriInfo, nextAction);
	}

	private boolean isVerifyEmailActionSet(UserModel user, AuthenticationSessionModel authSession) {
		return Stream.concat(user.getRequiredActionsStream(), authSession.getRequiredActions().stream())
			.anyMatch(UserModel.RequiredAction.VERIFY_EMAIL.name()::equals);
	}

	@Override
	public int order() {
		return super.order() + 10;
	}

	@Override
	public Map<String, String> getOperationalInfo() {
		return BuildDetails.get();
	}

}
