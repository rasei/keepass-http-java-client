/*
 * Copyright 2017 Ralf Seidengarn
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

import net.seidengarn.json.JSONParser;
import net.seidengarn.keepasshttp.client.exception.EncryptionException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpCommunicationException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpException;
import net.seidengarn.keepasshttp.client.exception.KeePassHttpNotAssociatedException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

/**
 * Connector for communication with a local KeePass with installed KeePassHttp-Plugin. By default the key and id will be
 * stored after successfull association.
 *
 * @author Ralf Seidengarn
 */
public class KeePassHttpConnector {

   private static final Log LOG = LogFactory.getLog(KeePassHttpConnector.class);
   private int port = 19455;
   private File keyFile;
   private String id;
   private String key;

   /**
    * Constructor tries to load the stored key and id
    */
   public KeePassHttpConnector() {
      this.keyFile = new File(FileUtils.getUserDirectory(), "keepasshttpclient.json");
      loadKey();
   }

   /**
    * Constructor
    * 
    * @param port port running KeePassHttp-Plugin (if different from default)
    */
   public KeePassHttpConnector(int port) {
      this();
      this.port = port;
   }

   /**
    * Constructor with a predefined id an key, both will not be stored
    * 
    * @param id Identifier for the client authenticated by the key as configured in the KeepassDatabase
    * @param key AES-Key
    */
   public KeePassHttpConnector(String id, String key) {
      this.id = id;
      this.key = key;
      this.keyFile = null;
   }

   /**
    * Gets a list of logins available for the specified URL
    * 
    * @param url URL to search for in the KeePassDatabase, by default this can also be the name of the entry in KDB
    * @param submitUrl optional URL
    * @return a List of KeePassLogin with 0 elements if no matching login was found
    * @throws KeePassHttpException exception during communication
    */
   @SuppressWarnings("unchecked")
   public List<KeePassLogin> getLogins(String url, String submitUrl) throws KeePassHttpException {
      try {
         try {
            testAssociate();
         } catch (KeePassHttpNotAssociatedException e) {
            LOG.info("KeePass is not associated, try to associate");
            associate();
         }

         if (url == null) {
            throw new KeePassHttpException("missing parameter url");
         }
         if (submitUrl == null) {
            submitUrl = url;
         }

         String iv = generateIv();

         Map<String, Object> map = new HashMap<>();
         map.put("RequestType", "get-logins");
         map.put("Id", id);
         map.put("Nonce", iv);
         map.put("Verifier", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key)));
         map.put("Url", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(url, iv, key)));
         map.put("SubmitUrl", Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(submitUrl, iv, key)));

         map = communicate(map);

         iv = (String) map.get("Nonce");
         List<KeePassLogin> loginList = new ArrayList<>();

         List<Object> entries = (List<Object>) map.get("Entries");
         for (Object entryObject : entries) {
            Map<String, Object> entryMap = (Map<String, Object>) entryObject;

            KeePassLogin login = new KeePassLogin();
            login.setName(EncryptionUtil.decrypt(Base64.getDecoder().decode((String) entryMap.get("Name")), iv,
                     key));
            login.setLogin(EncryptionUtil.decrypt(Base64.getDecoder().decode((String) entryMap.get("Login")), iv,
                     key));
            login.setPassword(EncryptionUtil.decrypt(
                     Base64.getDecoder().decode((String) entryMap.get("Password")), iv, key));

            loginList.add(login);
         }

         return loginList;
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }

   /**
    * Load the key (and id) from the filesystem
    */
   @SuppressWarnings("unchecked")
   private void loadKey() {
      if (keyFile != null) {
         try {
            String data = FileUtils.readFileToString(keyFile, Charset.forName("UTF-8"));
            Map<String, Object> map = (Map<String, Object>) JSONParser.parse(data);
            id = (String) map.get("Id");
            key = (String) map.get("Key");
         } catch (IOException e) {
            LOG.error("key could not be loaded");
         }
      }
   }

   /**
    * Stores the key (and id) in the filesystem
    * 
    * @throws KeePassHttpException
    */
   private void storeKey() throws KeePassHttpException {
      if (keyFile != null) {
         try {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put("Key", key);
            map.put("Id", id);
            String data = JSONParser.compose(map);

            FileUtils.writeStringToFile(keyFile, data, Charset.forName("UTF-8"));
         } catch (IOException e) {
            throw new KeePassHttpException("Exception while storing the key to communicate with KeePass", e);
         }
      }
   }

   void testAssociate() throws KeePassHttpException {
      if (id == null || key == null) {
         associate();
      }

      try {
         String iv = generateIv();
         String verifier = Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key));

         Map<String, Object> map = new HashMap<String, Object>();
         map.put("RequestType", "test-associate");
         map.put("Id", id);
         map.put("Nonce", iv);
         map.put("Verifier", verifier);
         map = communicate(map);
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }

   /**
    * Doing the communication with KeePass
    *
    * @param map request map
    * @return response map
    */
   @SuppressWarnings("unchecked")
   private Map<String, Object> communicate(Map<String, Object> map) throws KeePassHttpCommunicationException,
            KeePassHttpNotAssociatedException {
      try {

         RequestConfig config = RequestConfig.custom().setConnectTimeout(10000).setConnectionRequestTimeout(10000)
                  .setSocketTimeout(10000).build();
         CloseableHttpClient client = HttpClientBuilder.create().setDefaultRequestConfig(config).build();

         String request = JSONParser.compose(map);
         HttpPost postMethod = new HttpPost("http://localhost:" + port);
         StringEntity requestEntity = new StringEntity(request, "UTF-8");
         postMethod.setEntity(requestEntity);
         HttpResponse httpResponse = client.execute(postMethod);
         int result = httpResponse.getStatusLine().getStatusCode();
         if (result != HttpStatus.SC_OK) {
            throw new KeePassHttpCommunicationException("Communication with KeePass failed, http-returncode is "
                                                        + result + ", expected 200");
         }

         String responseBody = IOUtils.toString(httpResponse.getEntity().getContent(), Charset.forName("UTF-8"));
         map = (Map<String, Object>) JSONParser.parse(responseBody);

         if (map == null || map.get("Success") == null) {
            throw new KeePassHttpCommunicationException(
                     "Communication with KeePass failed, response from KeePassHttp is invalid");
         }

         if (!map.get("Success").equals("true")) {
            throw new KeePassHttpNotAssociatedException(
                     "Communication with KeePass failed, client is not associated with KeePassHttp");
         }
      } catch (IOException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
      return map;
   }

   private String generateIv() {
      byte[] ivArr = new byte[16];
      for (int i = 0; i < ivArr.length; i++) {
         ivArr[i] = (byte) RandomUtils.nextInt();
      }
      return Base64.getEncoder().encodeToString(ivArr);
   }

   void associate() throws KeePassHttpException {
      if (key == null) {
         key = generateIv();
      }

      try {
         String iv = generateIv();
         String verifier = Base64.getEncoder().encodeToString(EncryptionUtil.encrypt(iv, iv, key));

         Map<String, Object> map = new HashMap<String, Object>();
         map.put("RequestType", "associate");
         map.put("Key", key);
         map.put("Nonce", iv);
         map.put("Verifier", verifier);

         map = communicate(map);

         id = (String) map.get("Id");
         storeKey();
      } catch (EncryptionException e) {
         throw new KeePassHttpCommunicationException("Communication with KeePass failed", e);
      }
   }
}
