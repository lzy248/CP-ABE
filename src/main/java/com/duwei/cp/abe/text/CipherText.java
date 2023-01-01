package com.duwei.cp.abe.text;

import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.parameter.PublicKey;
import com.duwei.cp.abe.parameter.SystemKey;
import com.duwei.cp.abe.structure.AccessTree;
import com.duwei.cp.abe.structure.AccessTreeBuildModel;
import com.duwei.cp.abe.util.ObjectConvertUtil;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import lombok.Data;
import lombok.ToString;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import static com.duwei.cp.abe.parameter.PairingParameter.parametersPath;

/**
 * @BelongsProject: JPBC-ABE
 * @BelongsPackage: com.duwei.jpbc.cp.abe
 * @Author: duwei
 * @Date: 2022/7/21 16:41
 * @Description: 密文
 */
@Data
@ToString
public class CipherText {
    //g1
    private Element c_wave;
    //g0
    private Element c;
    //g0
    private Map<Attribute,Element> c_y_map;
    //g0
    private Map<Attribute,Element> c_y_pie_map;
    //访问树
    private AccessTree accessTree;

    public String toStr(){
        Map<String, Object> map = new HashMap<>();
        //c_wave字节化
        map.put("c_wave",this.c_wave.getImmutable().toBytes());
        //c字节化
        map.put("c",this.c.getImmutable().toBytes());
        //c_y_map变为可序列化map
        map.put("c_y_map",this.c_yToMap(this.c_y_map));
        //c_y_pie_map变为可序列化map
        map.put("c_y_pie_map",c_yToMap(this.c_y_pie_map));
        //accessTree序列化
        map.put("accessTreeBuildModels",accessTree.getAccessTreeBuildModels());
        //获取accessTree叶节点秘密值
        map.put("accessTreeLeafSecretNumber",accessTree.getLeafSecretNumber());
        return ObjectConvertUtil.objectToBase64(map);
    }


    public static CipherText fromStr(String str, SystemKey systemKey){
        Pairing pairing = systemKey.getPublicKey().getPairingParameter().getPairing();
        Map<String, Object> map = ObjectConvertUtil.base64ToObject(str);
        CipherText cipherText = new CipherText();
        //恢复c_wave
        byte[] c_wave_bytes = (byte[]) map.get("c_wave");
        Element c_wave = pairing.getGT().newElementFromBytes(c_wave_bytes).getImmutable();
        cipherText.setC_wave(c_wave);
        //恢复c
        byte[] c_bytes = (byte[]) map.get("c");
        Element c = pairing.getG1().newElementFromBytes(c_bytes).getImmutable();
        cipherText.setC(c);
        //恢复c_y_map
        Map<String,byte[]> c_y_map_map = (Map<String, byte[]>) map.get("c_y_map");
        Map<Attribute, Element> c_y_map = mapToC_y(c_y_map_map,systemKey.getPublicKey(),pairing);
        cipherText.setC_y_map(c_y_map);
        //恢复c_y_pie_map
        Map<String,byte[]> c_y_pie_map_map = (Map<String, byte[]>) map.get("c_y_pie_map");
        Map<Attribute, Element> c_y_pie_map = mapToC_y(c_y_pie_map_map,systemKey.getPublicKey(),pairing);
        cipherText.setC_y_pie_map(c_y_pie_map);
        //恢复accessTree
        AccessTreeBuildModel[] accessTreeBuildModels = (AccessTreeBuildModel[]) map.get("accessTreeBuildModels");
        AccessTree accessTree = AccessTree.build(systemKey.getPublicKey(), accessTreeBuildModels);
        //恢复叶节点秘密值
        Map<Integer,byte[]> leafSecretNumber = (Map<Integer, byte[]>) map.get("accessTreeLeafSecretNumber");
        accessTree.setLeafSecretNumber(leafSecretNumber,pairing);
        cipherText.setAccessTree(accessTree);

        return cipherText;
    }
    private Map<String,byte[]> c_yToMap(Map<Attribute,Element> c_y){
        Map<String, byte[]> map = new HashMap<>();
        for (Map.Entry<Attribute, Element> entry : c_y.entrySet()) {
            map.put(entry.getKey().getAttributeName(),entry.getValue().getImmutable().toBytes());
        }
        return map;
    }

    private static Map<Attribute,Element> mapToC_y(Map<String,byte[]> map, PublicKey publicKey, Pairing pairing){
        HashMap<Attribute, Element> c_y_map = new HashMap<>();
        for(Map.Entry<String, byte[]> entry : map.entrySet()){
            Attribute attribute = new Attribute(entry.getKey(),publicKey);
            Element element = pairing.getG1().newElementFromBytes(entry.getValue()).getImmutable();
            c_y_map.put(attribute,element);
        }
        return c_y_map;
    }

    public void putCy(Attribute attribute,Element cy){
        c_y_map.put(attribute,cy);
    }

    public void putCyPie(Attribute attribute,Element cy_pie){
        c_y_pie_map.put(attribute,cy_pie);
    }

    public Element getCy(Attribute attribute){
//        for (Map.Entry<Attribute, Element> entry : c_y_map.entrySet()) {
//            if(entry.getKey().getAttributeName().equals(attribute.getAttributeName())){
//                return entry.getValue();
//            }
//        }
//        return null;
        //修改了attribute的equal和hash方法
        return c_y_map.get(attribute);
    }

    public Element getCyPie(Attribute attribute){
//        for (Map.Entry<Attribute, Element> entry : c_y_pie_map.entrySet()) {
//            if(entry.getKey().getAttributeName().equals(attribute.getAttributeName())){
//                return entry.getValue();
//            }
//        }
//        return null;
        //修改了attribute的equal和hash方法
        return c_y_pie_map.get(attribute);
    }

    public CipherText() {
        c_y_map = new HashMap<>();
        c_y_pie_map = new HashMap<>();
    }
}
