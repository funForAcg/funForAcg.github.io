package blobkbhain.utils;

import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * sm2加密解密工具
 *
 * @since 2022-09-15
 */
@UtilityClass
@Slf4j
public class Sm2Util {

	// --------------------------------使用自定义密钥对加密或解密====开始------------------------------------

	/**
	 * 获取SM2公私钥对
	 *
	 * @return KeyPair
	 */
	public static KeyPair getSM2KeyPair() {
		return SecureUtil.generateKeyPair("SM2");
	}

	/**
	 * 获取自定义密钥的SM2
	 *
	 * @param privateKey 私钥,base64
	 * @param publicKey  公钥,base64
	 * @return SM2
	 */
	public static SM2 getCustomizeSM2(String privateKey, String publicKey) {
		return SmUtil.sm2(privateKey, publicKey);
	}

	/**
	 * 加密
	 *
	 * @param text      待加密字符串
	 * @param publicKey 公钥,base64
	 * @return String
	 */
	public static String customizeEncrypt(String text, String publicKey) {
		if (ObjectUtil.isNull(text)) {
			return null;
		}
		SM2 sm2 = Sm2Util.getCustomizeSM2(null, publicKey);
		// 公钥加密
		return sm2.encryptBcd(text, KeyType.PublicKey);
	}

	/**
	 * 解密
	 *
	 * @param text       待解密字符串
	 * @param privateKey 私钥,base64
	 * @return String
	 */
	public static String customizeDecrypt(String text, String privateKey) {
		SM2 sm2 = Sm2Util.getCustomizeSM2(privateKey, null);
		// 私钥解密
		return StrUtil.utf8Str(sm2.decryptFromBcd(text, KeyType.PrivateKey));
	}

	/**
	 * 使用私钥生成签名
	 *
	 * @param text       生成签名的内容
	 * @param privateKey 私钥,base64
	 * @return String
	 */
	public static String createSign(String text, String privateKey) {
		SM2 sm2 = Sm2Util.getCustomizeSM2(privateKey, null);
		return sm2.signHex(HexUtil.encodeHexStr(text));
	}

	/**
	 * 使用公钥验证签名
	 *
	 * @param text      生成签名的内容
	 * @param sign      签名
	 * @param publicKey 公钥,base64
	 * @return boolean
	 */
	public static boolean verifySign(String text, String sign, String publicKey) {
		SM2 sm2 = Sm2Util.getCustomizeSM2(null, publicKey);
		return sm2.verifyHex(HexUtil.encodeHexStr(text), sign);
	}
	// --------------------------------使用自定义密钥对加密或解密====结束------------------------------------

	/**
	 * 字节数组转Base64编码
	 *
	 * @param bytes 字节数组
	 * @return Base64编码
	 */
	public static String bytesToBase64(byte[] bytes) {
		byte[] encodedBytes = Base64.getEncoder().encode(bytes);
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

	/**
	 * Base64编码转字节数组
	 *
	 * @param base64Str Base64编码
	 * @return 字节数组
	 */
	public static byte[] base64ToBytes(String base64Str) {
		byte[] bytes = base64Str.getBytes(StandardCharsets.UTF_8);
		return Base64.getDecoder().decode(bytes);
	}

	/**
	 * 生成签名
	 *
	 * @param appId           appId
	 * @param acceptTimeStr   时间戳
	 * @param requestParams    new LinkedHashMap<>()生成签名的参数
	 * @param privateKeyClient 客户端私钥
	 */
	public static String createSign(String appId, String acceptTimeStr, LinkedHashMap<String, Object> requestParams, String privateKeyClient) {
		// 生成签名的参数,appid+时间戳+其他参数，其他参数按传入顺序拼接
		StringBuilder signParams = new StringBuilder();
		Set<Map.Entry<String, Object>> es = requestParams.entrySet();
		signParams.append(appId).append(acceptTimeStr);
		for (Map.Entry<String, Object> entry : es) {
			if (entry.getValue() != null) {
				String encodeValue = "";
				if (entry.getValue() instanceof String[] || entry.getValue() instanceof JSONArray || entry.getValue() instanceof JSONObject) {
					encodeValue = JSON.toJSONString(entry.getValue());
				} else if (ObjectUtil.isNotEmpty(entry.getValue())) {
					encodeValue = entry.getValue().toString();
				}
				signParams.append(encodeValue);
			}
		}
		// 验证SM2签名
		//log.info("签名str:{}", signParams);
		return Sm2Util.createSign(signParams.toString(), privateKeyClient);
	}
}
