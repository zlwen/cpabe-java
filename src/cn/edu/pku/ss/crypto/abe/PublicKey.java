package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;

import cn.edu.pku.ss.crypto.abe.serialize.Serializable;
import cn.edu.pku.ss.crypto.abe.serialize.SimpleSerializable;

public class PublicKey implements SimpleSerializable {
	@Serializable(group="G1")
	Element g; // G1 generator
	
	@Serializable(group="G2")
	Element gp; // G2 generator
	
	@Serializable(group="GT")
	Element g_hat_alpha; // GT
	
	@Serializable(group="G1")
	Element h; //G1

}
