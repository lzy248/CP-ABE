package com.duwei.cp.abe.util;

import java.io.*;
import java.util.Base64;
import java.util.Optional;

public class ObjectConvertUtil {
    public static <T> String objectToBase64(T obj){
        Optional<byte[]> bytes = objectToBytes(obj);
        if(bytes.isPresent()){
            return Base64.getEncoder().withoutPadding().encodeToString(bytes.get());
        }else{
            return "";
        }
    }

    public static <T> T base64ToObject(String str){
        byte[] decode = Base64.getDecoder().decode(str);
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
