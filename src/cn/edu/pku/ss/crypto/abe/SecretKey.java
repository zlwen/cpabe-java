package cn.edu.pku.ss.crypto.abe;

import cn.edu.pku.ss.crypto.abe.serialize.SimpleSerializable;
import it.unisa.dia.gas.jpbc.Element;

public class SecretKey implements SimpleSerializable{
	Element D;
	SKComponent[] comps;
	
	 public static class SKComponent implements SimpleSerializable{
		String attr;
		Element Dj;
		Element _Dj;
	}
}
