package com.duwei.cp.abe.text;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import lombok.Data;

import java.io.Serializable;

@Data
public class SerializableElement implements Serializable {
    private Boolean isNull;
    private int fieldIndex;
    private byte[] bytes;

    private SerializableElement() {
    }

    public static SerializableElement fromElement(Element element, Pairing pairing) {
        SerializableElement serializableElement = new SerializableElement();
        serializableElement.setIsNull(element == null);
        if (element == null) return serializableElement;
        serializableElement.setFieldIndex(pairing.getFieldIndex(element.getField()));
        serializableElement.setBytes(element.toBytes());
        return serializableElement;
    }

    public Element toElement(Pairing pairing) {
        if (this.getIsNull()) return null;
        return pairing.getFieldAt(this.getFieldIndex()).newElementFromBytes(this.getBytes());
    }
}
