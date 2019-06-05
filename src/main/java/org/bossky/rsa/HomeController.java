package org.bossky.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URLDecoder;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeController {

	private static final Logger _Logger = org.slf4j.LoggerFactory.getLogger(HomeController.class);

	@Autowired
	private RSAConfig config;

	@RequestMapping(value = "/")
	public String index(Model model) throws IOException {
		BigInteger modulus = config.getPublicModulus();
		model.addAttribute("bitLength", modulus.bitLength());
		model.addAttribute("modulus", modulus.toString(16).toUpperCase());
		return "demo";
	}

	@RequestMapping(value = "/submit.do")
	public String submit(Model model, String password) throws IOException {
		_Logger.info("密文:" + password);
		byte[] data = RSAUtil.decryptByPrivateKey(
				org.bouncycastle.util.encoders.Base64.decode(password), config.getPrivateKey());
		password = new String(data);
		_Logger.info("解密后:" + password);
		password = URLDecoder.decode(password, "UTF-8");
		_Logger.info("URL解码后:" + password);
		model.addAttribute("password", password);
		return "result";
	}

}
