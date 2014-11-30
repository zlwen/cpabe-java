package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.File;
import java.io.IOException;

import cn.edu.pku.ss.crypto.abe.serialize.SerializeUtils;

public class CPABE {
	private static Pairing pairing = PairingManager.defaultPairing;

	public static void main(String[] args) {
		setup();
	}
	
	public static void setup(String PKPath, String MKPath){
		File PKFile = new File(PKPath);
		File MKFile = new File(MKPath);
		if(!PKFile.exists()){
			try {
				PKFile.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		if(!MKFile.exists()){
			try {
				MKFile.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		PublicKey PK = new PublicKey();
		MasterKey MK = new MasterKey();
		
		Element alpha  = pairing.getZr().newElement().setToRandom();
		PK.g           = pairing.getG1().newElement().setToRandom();
		PK.gp          = pairing.getG2().newElement().setToRandom();
		MK.beta        = pairing.getZr().newElement().setToRandom();
		MK.g_alpha     = PK.gp.duplicate().powZn(alpha);
		PK.h           = PK.g.duplicate().powZn(MK.beta);
		PK.g_hat_alpha = pairing.pairing(PK.g, MK.g_alpha);
		
		System.out.println(PK.g);
		
		SerializeUtils.serialize(PK, PKFile);
		PublicKey _PK = SerializeUtils.unserialize(PublicKey.class, PKFile);
		System.out.println(_PK.g);
	}
	
	public static void setup(){
		String pk = "PubKey";
		String mk = "MasterKey";
		setup(pk, mk);
	}

	public static void keygen(){
		
	}

	public static void enc(){
		
	}

	public static void dec(){
		
	}
}
