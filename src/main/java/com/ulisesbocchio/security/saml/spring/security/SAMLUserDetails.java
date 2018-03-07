package com.ulisesbocchio.security.saml.spring.security;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLCredential;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Ulises Bocchio
 */
public class SAMLUserDetails implements UserDetails {

    private SAMLCredential samlCredential;

    public SAMLUserDetails(SAMLCredential samlCredential) {
        this.samlCredential = samlCredential;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return samlCredential.getNameID().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public String getAttribute(String name) {
        return samlCredential.getAttributeAsString(name);
    }

    public Map<String, String> getAttributes() {
        return samlCredential.getAttributes().stream()
                .collect(Collectors.toMap(Attribute::getName, this::getValue));
    }

    private String getValue(Attribute attribute) {
        List<XMLObject> attributeValues = attribute.getAttributeValues();
        if (attributeValues == null || attributeValues.size() == 0) {
            return null;
        }
        XMLObject xmlValue = attributeValues.iterator().next();
        return getString(xmlValue);
    }

    private String getString(XMLObject xmlValue) {
        if (xmlValue instanceof XSString) {
            return ((XSString) xmlValue).getValue();
        } else if (xmlValue instanceof XSAny) {
            return ((XSAny) xmlValue).getTextContent();
        } else {
            return null;
        }
    }
}
