"""
XML templates for SAML 2.0 SP
"""
from flask_saml2.xml_templates import NameIDTemplate, XmlTemplate


class AuthnRequest(XmlTemplate):
    namespace = 'samlp'

    def get_issuer(self):
        namespace = self.get_namespace_map()['saml']
        return self.element('Issuer', namespace=namespace, text=self.params['ISSUER'])

    def get_name_id(self):
        namespace = self.get_namespace_map()['samlp']
        return self.element("NameIDPolicy", namespace=namespace, attrs={
            "AllowCreate": "true",
            "Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        })

    def get_requested_authn_context(self):
        saml_namespace = self.get_namespace_map()['saml']
        samlp_namespace = self.get_namespace_map()['samlp']
        return self.element("RequestedAuthnContext", namespace=samlp_namespace, attrs={
            "Comparison": "exact",
        }, children=[
            self.element("AuthnContextClassRef", namespace=saml_namespace,
                         text="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
        ])

    def generate_xml(self):
        return self.element('AuthnRequest', attrs={
            # 'xmlns:samlp': "urn:oasis:names:tc:SAML:2.0:protocol",
            # 'xmlns:saml': "urn:oasis:names:tc:SAML:2.0:assertion",
            'ID': self.params['REQUEST_ID'],
            'Version': '2.0',
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Destination': self.params['DESTINATION'],
            "ForceAuthn": "true",
            "IsPassive": "false",
            'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'AssertionConsumerServiceURL': self.params['ACS_URL'],
        }, children=[
            self.get_issuer(),
            self.get_name_id()
        ])

    """
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        ID="ONELOGIN_8dff24c0cff932be98212185538bb8da630699c7"
                        Version="2.0"${PROVIDER_NAME}
                        IssueInstant="${ISSUE_INSTANT}"
                        Destination="${DESTINATION}"
                        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        AssertionConsumerServiceURL="${ACS_URL}"
                        >
        <saml:Issuer>${ENTITY_ID}</saml:Issuer>
        <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
    </samlp:AuthnRequest>"""


class LogoutRequest(XmlTemplate):
    namespace = 'samlp'

    def get_issuer(self):
        namespace = self.get_namespace_map()['saml']
        return self.element('Issuer', namespace=namespace, text=self.params['ISSUER'])

    def get_nameid(self):
        return NameIDTemplate(self.params).xml

    def get_session_index(self):
        return None

    def generate_xml(self):
        return self.element('LogoutRequest', attrs={
            'ID': self.params['REQUEST_ID'],
            'Version': '2.0',
            'IssueInstant': self.params['ISSUE_INSTANT'],
            'Destination': self.params['DESTINATION'],
        }, children=[
            self.get_issuer(),
            self.get_nameid(),
            self.get_session_index(),
        ])

    """
    <samlp:LogoutRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="${ID}"
        Version="2.0"
        IssueInstant="${ISSUE_INSTANT}"
        Destination="${SINGLE_LOGOUT_URL}">
        <saml:Issuer>${ENTITY_ID}</saml:Issuer>
        ${NAME_ID}
        ${SESSION_INDEX}
    </samlp:LogoutRequest>
    """
