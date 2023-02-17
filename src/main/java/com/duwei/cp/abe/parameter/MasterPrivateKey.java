package com.duwei.cp.abe.parameter;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;
import lombok.ToString;

/**
 * @BelongsProject: JPBC-ABE
 * @BelongsPackage: com.duwei.jpbc.cp.abe
 * @Author: duwei
 * @Date: 2022/7/21 16:27
 * @Description: 系统主私钥 the master key MK is (β,g^α)
 */
@Data
@ToString
public class MasterPrivateKey extends Key {
    /**
     * beta in Z_p
     */
    private Element beta;
    /**
     * g pow alpha
     */
    private Element g_alpha;
    /**
     * alpha
     */
    private Element alpha;


    public MasterPrivateKey() {

    }

    public MasterPrivateKey(PairingParameter parameter) {
        super(parameter);
    }

    public static MasterPrivateKey build(PairingParameter parameter) {
        MasterPrivateKey masterPrivateKey = new MasterPrivateKey(parameter);
        //随机生成alpha和beta ∈ Z_p
        masterPrivateKey.setBeta(parameter.getZr().newRandomElement().getImmutable());
        masterPrivateKey.setAlpha(parameter.getZr().newRandomElement().getImmutable());
        masterPrivateKey.setG_alpha((parameter.getGenerator().powZn(masterPrivateKey.getAlpha())).getImmutable());
        return masterPrivateKey;
    }


}
