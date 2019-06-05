package org.bossky.rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
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

	public static PrivateKey getPrivateKeyFromPem(File pem) throws IOException {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(pem));
			String s = br.readLine();
			String str = "";
			s = br.readLine();
			while (s.charAt(0) != '-') {
				str += s + "\r";
				s = br.readLine();
			}
			byte[] data = Base64.decode(str);
			return getPrivateKey(data);
		} finally {
			if (null != br) {
				br.close();
			}
		}
	}

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
	 * 从pem中获取publicKey
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	public static PublicKey getPublicKeyFromPem(File pem) throws IOException {
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(pem));
			String s = br.readLine();
			String str = "";
			s = br.readLine();
			while (s.charAt(0) != '-') {
				str += s + "\r";
				s = br.readLine();
			}
			byte[] data = Base64.decode(str);
			return getPublicKey(data);
		} finally {
			if (null != br) {
				br.close();
			}
		}
	}

	/**
	 * 从base64字节中获取publickey
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

	public static void main(String[] args) {

		try {
			PublicKey publicKey = getPublicKey(Base64.decode(
					"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy+h9lm1R6tyL3kbC98qj6Z4peB9KJx5oNXxNElXEUF7w4LPbGL814v2ay8J+SDj0rCBs6jOjxEHbIIVhM+U0bLvNpqdn2w01bEXd5iQsSqV8DcVBupwFA9Io6wplB7SkZSoxuGl/ooO7ws15PFedQxWP9dhLOX+LqVgI84kxVw5Mn8V6pnD2s4KKfxz8mzYCxLW3OWNHsxQWZ2E4ymM2XUP/GSO7/7RnfpWQKXLQ96xDI9Y1Ji+S25MJjusXLvJl5rHQx2mvGZLz2TlQ4+NS4Tzjm21ln3Epfv+PYkUHG6YA4NOLXmAjCd66gOY+AAA9Pe57hJ0giof4Cz6M4NZAIQIDAQAB"));
			System.out.println(publicKey);
			RSAPublicKey k = (RSAPublicKey) publicKey;
			BigInteger modulus = k.getModulus();
			System.out.println(modulus.bitLength());
			System.out.println(modulus.toString(16));
			System.out.println(getKeyFactory().getAlgorithm());
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
