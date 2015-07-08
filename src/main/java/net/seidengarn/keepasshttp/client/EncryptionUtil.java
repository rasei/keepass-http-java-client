package net.seidengarn.keepasshttp.client;

import net.seidengarn.keepasshttp.client.exception.EncryptionException;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {

   static byte[] encrypt(String plainText, String iv, String encryptionKey) throws EncryptionException {
      try {
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
         SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
         cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(iv)));
         return cipher.doFinal(plainText.getBytes("UTF-8"));
      } catch (NoSuchAlgorithmException e) {
         throw new EncryptionException(e);
      } catch (NoSuchProviderException e) {
         throw new EncryptionException(e);
      } catch (NoSuchPaddingException e) {
         throw new EncryptionException(e);
      } catch (InvalidKeyException e) {
         throw new EncryptionException(e);
      } catch (InvalidAlgorithmParameterException e) {
         throw new EncryptionException(e);
      } catch (IllegalBlockSizeException e) {
         throw new EncryptionException(e);
      } catch (BadPaddingException e) {
         throw new EncryptionException(e);
      } catch (UnsupportedEncodingException e) {
         throw new EncryptionException(e);
      }
   }

   static String decrypt(byte[] cipherText, String iv, String encryptionKey) throws NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
      SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
      cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(iv)));
      return new String(cipher.doFinal(cipherText), "UTF-8");
   }

}
