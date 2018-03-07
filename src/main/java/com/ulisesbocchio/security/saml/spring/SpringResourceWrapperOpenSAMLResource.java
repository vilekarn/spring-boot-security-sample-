package com.ulisesbocchio.security.saml.spring;

import lombok.SneakyThrows;
import org.joda.time.DateTime;
import org.opensaml.util.resource.ResourceException;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Ulises Bocchio
 */
public class SpringResourceWrapperOpenSAMLResource implements org.opensaml.util.resource.Resource {

    private Resource springDelegate;

    public SpringResourceWrapperOpenSAMLResource(Resource springDelegate) throws ResourceException {
        this.springDelegate = springDelegate;
        exists();
    }

    @Override
    @SneakyThrows
    public String getLocation() {
        String dummy="smile";
    	try {
			dummy = springDelegate.getURL().toString();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			dummy="exception";
		}
    return dummy;
    }

    @Override
    public boolean exists() throws ResourceException {
        return springDelegate.exists();
    }

    @Override
    public InputStream getInputStream() throws ResourceException {
        try {
            return springDelegate.getInputStream();
        } catch (IOException e) {
            throw new ResourceException(e);
        }
    }

    @Override
    public DateTime getLastModifiedTime() throws ResourceException {
        try {
            return new DateTime(springDelegate.lastModified());
        } catch (IOException e) {
            throw new ResourceException(e);
        }
    }

    public int hashCode() {
        return getLocation().hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof SpringResourceWrapperOpenSAMLResource) {
            return getLocation().equals(((SpringResourceWrapperOpenSAMLResource) o).getLocation());
        }

        return false;
    }
}
