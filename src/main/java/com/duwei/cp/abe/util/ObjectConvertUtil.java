package com.duwei.cp.abe.util;

import java.io.*;
import java.util.Base64;
import java.util.Optional;

public class ObjectConvertUtil {
    public static String byteArrayToBase64(byte[] bytes){
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] base64ToByteArray(String str){
        return Base64.getDecoder().decode(str);
    }


    public static <T> String objectToBase64(T obj){
        Optional<byte[]> bytes = objectToBytes(obj);
        if(bytes.isPresent()){
            return byteArrayToBase64(bytes.get());
        }else{
            return "";
        }
    }

    public static <T> T base64ToObject(String str){
        byte[] decode = base64ToByteArray(str);
        Optional<Object> obj = ObjectConvertUtil.bytesToObject(decode);
        return (T) obj.orElse(null);
    }


    public static <T> Optional<byte[]> objectToBytes(T obj) {
        byte[] bytes = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream sOut;
        try {
            sOut = new ObjectOutputStream(out);
            sOut.writeObject(obj);
            sOut.flush();
            bytes = out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Optional.ofNullable(bytes);
    }

    public static <T> Optional<T> bytesToObject(byte[] bytes) {
        T t = null;
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        ObjectInputStream sIn;
        try {
            sIn = new ObjectInputStream(in);
            t = (T) sIn.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.ofNullable(t);

    }
}
