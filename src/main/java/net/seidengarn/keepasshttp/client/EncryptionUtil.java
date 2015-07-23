/*
 * Copyright 2015 Ralf Seidengarn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */
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

/**
 * Utility-class for Encryption and Decryption
 *
 * @author Ralf Seidengarn
 */
public class EncryptionUtil {

   /**
    * Encrypt a text with AES/CBC
    *
    * @param plainText plain text
    * @param iv
    * @param encryptionKey
    * @return encrypted text as byte-array
    * @throws EncryptionException exception instead of detailled exception which may occur during encryption
    */
   static byte[] encrypt(String plainText, String iv, String encryptionKey) throws EncryptionException {
      try {
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
         SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
         cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(iv)));
         return cipher.doFinal(plainText.getBytes("UTF-8"));
      } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
               | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
               | UnsupportedEncodingException e) {
         throw new EncryptionException(e);
      }
   }

   static String decrypt(byte[] cipherText, String iv, String encryptionKey) throws EncryptionException {
      try {
         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
         SecretKeySpec key = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
         cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(Base64.getDecoder().decode(iv)));
         return new String(cipher.doFinal(cipherText), "UTF-8");
      } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
               | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
               | UnsupportedEncodingException e) {
         throw new EncryptionException(e);
      }
   }

}
