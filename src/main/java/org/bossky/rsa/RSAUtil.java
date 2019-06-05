package org.bossky.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Base64;

/**
 * RSA工具类
 * 
 * @author daibo
 *
 */
public class RSAUtil {
	// key算法 rsa
	private static final String KEY_ALGORITHM = "RSA";

	static {
		// 增加供应商
		java.security.Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	private RSAUtil() {

	}

	/**
	 * 从pem中获取PrivateKey
	 * 
	 * @param pem
	 * @return
	 * @throws IOException
	 */
	public static PrivateKey getPrivateKeyFromPem(File pem) throws IOException {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(pem));
			String s = br.readLine();
			StringBuilder sb = new StringBuilder();
			s = br.readLine();
			while (s.charAt(0) != '-') {
				sb.append(s).append("\r");
				s = br.readLine();
			}
			byte[] data = Base64.decode(sb.toString());
			return getPrivateKey(data);
		} finally {
			if (null != br) {
				br.close();
			}
		}
	}

	/**
	 * 从base64字节中获取PrivateKey
	 * 
	 * @param data
	 * @return
	 * @throws IOException
	 */
	public static PrivateKey getPrivateKey(byte[] data) throws IOException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
		PrivateKey privateKey;
		try {
			privateKey = getKeyFactory().generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		return privateKey;
	}

	/**
	 * 从pem中获取PublicKey
	 * 
	 * @param pem
	 * @return
	 * @throws IOException
	 */
	public static PublicKey getPublicKeyFromPem(File pem) throws IOException {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(pem));
			String s = br.readLine();
			StringBuilder sb = new StringBuilder();
			s = br.readLine();
			while (s.charAt(0) != '-') {
				sb.append(s).append("\r");
				s = br.readLine();
			}
			byte[] data = Base64.decode(sb.toString());
			return getPublicKey(data);
		} finally {
			if (null != br) {
				br.close();
			}
		}
	}

	/**
	 * 从base64字节中获取PublicKey
	 * 
	 * @param data
	 * @return
	 * @throws IOException
	 */
	public static PublicKey getPublicKey(byte[] data) throws IOException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
		PublicKey pubKey;
		try {
			pubKey = getKeyFactory().generatePublic(keySpec);
		} catch (InvalidKeySpecException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		return pubKey;
	}

	/**
	 * 私钥解密
	 *
	 * @param data
	 *            密文
	 * @param PrivateKey
	 *            私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, PrivateKey privateKey)
			throws IOException {
		Cipher cipher = getCipher();
		try {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		} catch (InvalidKeyException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IOException("解密失败", e);
		}
	}

	/**
	 * 用公钥解密
	 *
	 * @param data
	 *            密文
	 * @param publicKey
	 *            公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, PublicKey publicKey) throws IOException {
		Cipher cipher = getCipher();
		try {
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
		} catch (InvalidKeyException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IOException("解密失败", e);
		}
	}

	/**
	 * 用公钥加密
	 *
	 * @param data
	 *            明文
	 * @param PublicKey
	 *            公钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, PublicKey publicKey) throws IOException {
		Cipher cipher = getCipher();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		} catch (InvalidKeyException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IOException("加密失败", e);
		}
	}

	/**
	 * 用私钥加密
	 *
	 * @param data
	 *            明文
	 * @param privateKey
	 *            私钥
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey)
			throws IOException {
		Cipher cipher = getCipher();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		} catch (InvalidKeyException e) {
			throw new UnsupportedOperationException("无效Key", e);
		}
		try {
			return cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new IOException("加密失败", e);
		}
	}

	// 获取密文
	private static Cipher getCipher() {
		try {
			return Cipher.getInstance(KEY_ALGORITHM);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new UnsupportedOperationException("无效算法", e);
		}
	}

	// 获取key工厂
	private static KeyFactory getKeyFactory() {
		KeyFactory kf;
		try {
			kf = KeyFactory.getInstance(KEY_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("无效算法", e);
		}
		return kf;
	}

}
