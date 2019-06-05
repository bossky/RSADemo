package org.bossky.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

@Component
@Configuration
@ConfigurationProperties(prefix = "rsa")
// PropertySource默认取application.properties
//@PropertySource(value = "config.properties")
public class RSAConfig {

	protected String privateKeyPath;

	protected String publicKeyPath;

	protected PublicKey m_PublicKey;

	protected PrivateKey m_PrivateKey;

	public void setPrivateKeyPath(String v) {
		privateKeyPath = v;
	}

	public String getPrivateKeyPath() {
		return privateKeyPath;
	}

	public void setPublicKeyPath(String v) {
		publicKeyPath = v;
	}

	public String getPublicKeyPath() {
		return publicKeyPath;
	}

	public BigInteger getPublicModulus() throws IOException {
		PublicKey key = getPublicKey();
		if (key instanceof RSAPublicKey) {
			return ((RSAPublicKey) key).getModulus();
		} else {
			throw new UnsupportedOperationException("无效key:" + key);
		}
	}

	public PublicKey getPublicKey() throws IOException {
		if (null == m_PublicKey) {
			m_PublicKey = RSAUtil
					.getPublicKeyFromPem(ResourceUtils.getFile("classpath:" + getPublicKeyPath()));
		}
		return m_PublicKey;

	}

	public PrivateKey getPrivateKey() throws IOException {
		if (null == m_PrivateKey) {
			m_PrivateKey = RSAUtil
					.getPrivateKeyFromPem(ResourceUtils.getFile("classpath:" + privateKeyPath));
		}
		return m_PrivateKey;
	}
}
