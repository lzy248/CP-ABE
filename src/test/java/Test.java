import com.duwei.cp.abe.engine.CpAneEngine;
import com.duwei.cp.abe.parameter.PublicKey;
import com.duwei.cp.abe.parameter.SystemKey;
import com.duwei.cp.abe.structure.AccessTree;
import com.duwei.cp.abe.structure.AccessTreeBuildModel;
import com.duwei.cp.abe.text.CipherText;
import com.duwei.cp.abe.text.PlainText;
import com.duwei.cp.abe.util.FileStoreUtils;
import com.duwei.cp.abe.util.ObjectConvertUtil;
import it.unisa.dia.gas.jpbc.Element;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class Test {

    @org.junit.Test
    public void setUp() throws IOException {
        SystemKey systemKey = SystemKey.build();
        FileStoreUtils.storeSystemKey("/key/", systemKey);
    }

    @org.junit.Test
    public void getKey() throws IOException {
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        System.out.println(systemKey);

    }

    @org.junit.Test
    public void convert() throws IOException {
        CpAneEngine cpAneEngine = new CpAneEngine();
        SystemKey systemKey = FileStoreUtils.getSystemKey("/key/");
        String plainTextStr = "你好，CP - ABE，我是JPBC";
        PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
        AccessTree accessTree = getAccessTree(systemKey.getPublicKey());
        CipherText cipherText = cpAneEngine.encrypt(systemKey.getPublicKey(), plainText, accessTree);
        System.out.println("cipherText : " + cipherText);
        Optional<byte[]> bytes = ObjectConvertUtil.objectToBytes(cipherText);
        bytes.ifPresent(value -> {
            String s = Base64.getEncoder().withoutPadding().encodeToString(value);
            System.out.println(s);
        });
    }

    public static AccessTree getAccessTree(PublicKey publicKey) {
        AccessTreeBuildModel[] accessTreeBuildModels = new AccessTreeBuildModel[4];
        //根节点ID必须为1
        accessTreeBuildModels[0] = AccessTreeBuildModel.innerAccessTreeBuildModel(1, 1, 1, -1);
        accessTreeBuildModels[1] = AccessTreeBuildModel.leafAccessTreeBuildModel(2, 4, "1", 1);
        accessTreeBuildModels[2] = AccessTreeBuildModel.leafAccessTreeBuildModel(3, 2, "2", 1);
        accessTreeBuildModels[3] = AccessTreeBuildModel.leafAccessTreeBuildModel(4, 3, "3", 1);
        return AccessTree.build(publicKey, accessTreeBuildModels);
    }
@org.junit.Test
    public void testToByte() throws UnsupportedEncodingException {
        Map<String,Object> map = new HashMap<>();
        map.put("haha","1");
        map.put("xixxi","23");
        Optional<byte[]> bytes = ObjectConvertUtil.objectToBytes(map);
        bytes.ifPresent(value -> {
            String s = Base64.getEncoder().withoutPadding().encodeToString(value);
            System.out.println(s);
        });
    }
    @org.junit.Test
    public void testToObject(){

        String s = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAADdAADaGhhdXIAAltCrPMX+AYIVOACAAB4cAAAAAQAAQABdAAEaGFoYXQAATF0AAV4aXh4aXQAAjIzeA";
        Map<String,Object> map = ObjectConvertUtil.base64ToObject(s);
        byte[] b = (byte[]) map.get("hha");
        System.out.println(new String(b));
    }
}
