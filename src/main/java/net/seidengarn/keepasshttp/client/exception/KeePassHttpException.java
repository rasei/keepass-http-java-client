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
package net.seidengarn.keepasshttp.client.exception;

/**
 * exception while using KeePassHttp-Java-Connector
 *
 * @author Ralf Seidengarn
 */
public class KeePassHttpException extends Exception {

   public KeePassHttpException() {
   }

   public KeePassHttpException(String a) {
      super(a);
   }

   public KeePassHttpException(String a, Throwable t) {
      super(a, t);
   }

   public KeePassHttpException(Throwable t) {
      super(t);
   }

}
