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
package net.seidengarn.json;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A Parser for a JSON-String
 *
 * @author Ralf Seidengarn
 * @version $Revision$
 */
public class JSONParser {

   public static Object parse(String json) {
      if (json.startsWith("{")) {
         return parseObject(json);
      } else if (json.startsWith("[")) {
         return parseArray(json);
      } else {
         throw new UnsupportedOperationException("json-String must beginn / end with curly braces");
      }
   }

   private static Map<String, Object> parseObject(String json) {
      Map<String, Object> keyValuePairs = new HashMap<String, Object>();
      if (!json.startsWith("{") || !json.endsWith("}")) {
         throw new UnsupportedOperationException("json-String must beginn / end with curly braces");
      }

      String key = "";
      String valueString = "";
      int brace = 0;
      ParseModus modus = ParseModus.KEY;

      for (int i = 1; i < json.length(); i++) {
         char ch = json.charAt(i);
         switch (modus) {
         case KEY:
            if (ch == '\"') {
               continue;
            } else if (ch == ':') {
               modus = ParseModus.VALUE;
            } else {
               key += ch;
            }
            break;
         case VALUE:
            if (ch == '\"') {
               modus = ParseModus.VALUE_QUOTE;
            } else if (ch == '[') {
               modus = ParseModus.ARRAY;
               brace = 1;
               valueString += ch;
            } else if (ch == '{') {
               modus = ParseModus.VALUE_OBJECT;
               brace = 1;
               valueString += ch;
            } else if (ch == ',' || ch == '}') {
               modus = ParseModus.KEY;
               keyValuePairs.put(key, valueString);
               key = "";
               valueString = "";
            } else {
               valueString += ch;
            }
            break;
         case VALUE_QUOTE:
            if (ch == '\"') {
               modus = ParseModus.VALUE;
            } else {
               valueString += ch;
            }
            break;
         case VALUE_OBJECT:
            valueString += ch;
            if (ch == '{') {
               brace++;
            } else if (ch == '}') {
               brace--;
               if (brace == 0) {
                  modus = ParseModus.KEY;
                  keyValuePairs.put(key, parse(valueString));
                  key = "";
                  valueString = "";
                  if (json.charAt(i + 1) == ',') {
                     i++;
                  }
               }
            }
            break;
         case ARRAY:
            valueString += ch;
            if (ch == '[') {
               brace++;
            } else if (ch == ']') {
               brace--;
               if (brace == 0) {
                  modus = ParseModus.KEY;
                  keyValuePairs.put(key, parseArray(valueString));
                  key = "";
                  valueString = "";
                  if (json.charAt(i + 1) == ',') {
                     i++;
                  }
               }
            }
            break;
         }
      }

      return keyValuePairs;
   }

   private static List<Object> parseArray(String json) {
      List<Object> values = new ArrayList<Object>();

      if (!json.startsWith("[") || !json.endsWith("]")) {
         throw new UnsupportedOperationException("json-Arraystring must beginn / end with brackets");
      }

      String valueString = "";
      int brace = 0;
      ArrayParseModus modus = ArrayParseModus.VALUE;

      for (int i = 1; i < json.length(); i++) {
         char ch = json.charAt(i);
         switch (modus) {
         case VALUE:
            if (ch == '\"') {
               modus = ArrayParseModus.VALUE_QUOTE;
            } else if (ch == '[') {
               modus = ArrayParseModus.ARRAY;
               brace = 1;
               valueString += ch;
            } else if (ch == '{') {
               modus = ArrayParseModus.VALUE_OBJECT;
               brace = 1;
               valueString += ch;
            } else if (ch == ',' || ch == ']') {
               if (valueString.length() > 0) {
                  values.add(valueString);
                  valueString = "";
               }
            } else {
               valueString += ch;
            }
            break;
         case VALUE_QUOTE:
            if (ch == '\"') {
               modus = ArrayParseModus.VALUE;
            } else {
               valueString += ch;
            }
            break;
         case VALUE_OBJECT:
            valueString += ch;
            if (ch == '{') {
               brace++;
            } else if (ch == '}') {
               brace--;
               if (brace == 0) {
                  modus = ArrayParseModus.VALUE;
                  values.add(parse(valueString));
                  valueString = "";
                  if (json.charAt(i + 1) == ',') {
                     i++;
                  }
               }
            }
            break;
         case ARRAY:
            valueString += ch;
            if (ch == '[') {
               brace++;
            } else if (ch == ']') {
               brace--;
               if (brace == 0) {
                  modus = ArrayParseModus.VALUE;
                  values.add(parseArray(valueString));
                  valueString = "";
                  if (json.charAt(i + 1) == ',') {
                     i++;
                  }
               }
            }
            break;
         }
      }

      return values;
   }

   static enum ParseModus {
      KEY, VALUE, VALUE_QUOTE, VALUE_OBJECT, ARRAY
   }

   static enum ArrayParseModus {
      VALUE, VALUE_QUOTE, VALUE_OBJECT, ARRAY
   }

   private static String compose(List list) {
      String result = "[";

      for (Object element : list) {
         if (result.length() > 1) {
            result += ",";
         }
         result += compose(element);
      }

      result += "]";
      return result;
   }

   public static String compose(Map<String, Object> map) {
      String result = "{";

      for (String key : map.keySet()) {
         if (result.length() > 1) {
            result += ",";
         }
         result += "\"" + key + "\":";
         result += compose(map.get(key));
      }

      result += "}";
      return result;
   }

   private static String compose(Object value) {
      if (value instanceof String) {
         String st = (String) value;
         return "\"" + st + "\"";
      } else if (value instanceof Map) {
         return compose((Map<String, Object>) value);
      } else if (value instanceof List) {
         return compose((List) value);
      } else {
         throw new UnsupportedOperationException("unsupported object-type: " + value.getClass().getName());
      }
   }
}
