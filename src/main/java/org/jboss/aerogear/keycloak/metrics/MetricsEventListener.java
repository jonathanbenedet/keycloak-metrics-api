package org.jboss.aerogear.keycloak.metrics;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

public class MetricsEventListener implements EventListenerProvider {

    public final static String ID = "metrics-listener";

    private final static Logger logger = Logger.getLogger(MetricsEventListener.class);

    private KeycloakSession keycloakSession;

    public MetricsEventListener(KeycloakSession session) {
        this.keycloakSession = session;
    }

    @Override
    public void onEvent(Event event) {
        logEventDetails(event);
        RealmModel realm = keycloakSession.realms().getRealm(event.getRealmId());
        event.setRealmId(realm.getName().replaceAll("[^A-Za-z0-9.]", "_"));
        switch (event.getType()) {
            case LOGIN:
                PrometheusExporter.instance().recordLogin(event);
                break;
            case CLIENT_LOGIN:
                PrometheusExporter.instance().recordClientLogin(event);
                break;
            case REGISTER:
                PrometheusExporter.instance().recordRegistration(event);
                break;
            case REFRESH_TOKEN:
                PrometheusExporter.instance().recordRefreshToken(event);
                break;
            case CODE_TO_TOKEN:
                PrometheusExporter.instance().recordCodeToToken(event);
                break;
            case REGISTER_ERROR:
                PrometheusExporter.instance().recordRegistrationError(event);
                break;
            case LOGIN_ERROR:
                PrometheusExporter.instance().recordLoginError(event);
                break;
            case CLIENT_LOGIN_ERROR:
                PrometheusExporter.instance().recordClientLoginError(event);
                break;
            case REFRESH_TOKEN_ERROR:
                PrometheusExporter.instance().recordRefreshTokenError(event);
                break;
            case CODE_TO_TOKEN_ERROR:
                PrometheusExporter.instance().recordCodeToTokenError(event);
                break;
            default:
                PrometheusExporter.instance().recordGenericEvent(event);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        RealmModel realm = keycloakSession.realms().getRealm(event.getRealmId());
        event.setRealmId(realm.getName().replaceAll("[^A-Za-z0-9.]", "_"));
        logAdminEventDetails(event);

        PrometheusExporter.instance().recordGenericAdminEvent(event);
    }

    private void logEventDetails(Event event) {
        logger.debugf("Received user event of type %s in realm %s",
            event.getType().name(),
            event.getRealmId());
    }

    private void logAdminEventDetails(AdminEvent event) {
        logger.debugf("Received admin event of type %s (%s) in realm %s",
            event.getOperationType().name(),
            event.getResourceType().name(),
            event.getRealmId());
    }

    @Override
    public void close() {
        // unused
    }
}
