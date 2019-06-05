package org.bossky.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

/**
 * RSA配置
 * 
 * @author daibo
 *
 */
@Configuration
@ConfigurationProperties(prefix = "rsa")
// PropertySource默认取application.properties
//@PropertySource(value = "config.properties")
public class RSAConfig {
	/** 私钥路径 */
	protected String privateKeyPath;
	/** 公钥路径 */
	protected String publicKeyPath;
	/** 私钥 */
	protected PublicKey m_PublicKey;
	/** 公钥 */
	protected PrivateKey m_PrivateKey;

	public RSAConfig() {

	}

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

	/**
	 * 获取公钥Modulus
	 * 
	 * @return
	 * @throws IOException
	 */
	public BigInteger getPublicModulus() throws IOException {
		PublicKey key = getPublicKey();
		if (key instanceof RSAPublicKey) {
			return ((RSAPublicKey) key).getModulus();
		} else {
			throw new UnsupportedOperationException("无效key:" + key);
		}
	}

	/**
	 * 获取公钥
	 * 
	 * @return
	 * @throws IOException
	 */
	public PublicKey getPublicKey() throws IOException {
		if (null == m_PublicKey) {
			m_PublicKey = RSAUtil
					.getPublicKeyFromPem(ResourceUtils.getFile("classpath:" + getPublicKeyPath()));
		}
		return m_PublicKey;

	}

	/**
	 * 获取私钥
	 * 
	 * @return
	 * @throws IOException
	 */
	public PrivateKey getPrivateKey() throws IOException {
		if (null == m_PrivateKey) {
			m_PrivateKey = RSAUtil
					.getPrivateKeyFromPem(ResourceUtils.getFile("classpath:" + privateKeyPath));
		}
		return m_PrivateKey;
	}
}
