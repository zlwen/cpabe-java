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
	
	public static void setup(String PKFileName, String MKFileName){
		File PKFile = new File(PKFileName);
		File MKFile = new File(MKFileName);
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
		
//		SerializeUtils.serialize(PK, PKFile);
//		SerializeUtils.serialize(MK, MKFile);
		String[] attrs = new String[]{"PKU", "Student"};
		keygen(attrs, PK, MK, null);
	}
	
	public static void setup(){
		String pk = "PubKey";
		String mk = "MasterKey";
		setup(pk, mk);
	}

	public static void keygen(String[] attrs, PublicKey PK, MasterKey MK, String SKFileName){
		if(SKFileName == null || SKFileName.trim().equals("")){
			SKFileName = "SecretKey";
		}
		File SKFile = new File(SKFileName);
		if(!SKFile.exists()){
			try {
				SKFile.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		SecretKey SK = new SecretKey();
		Element r = pairing.getZr().newElement().setToRandom();
		Element g_r = PK.gp.duplicate().powZn(r);
		SK.D = MK.g_alpha.duplicate().mul(g_r);
		Element beta_inv = MK.beta.duplicate().invert();
		SK.D.powZn(beta_inv);
		SK.comps = new SecretKey.SKComponent[attrs.length];
		
		for(int i=0; i<attrs.length; i++){
			Element rj = pairing.getZr().newElement().setToRandom();
			Element hash = pairing.getG2().newElementFromBytes(attrs[i].getBytes()).powZn(rj);
			SK.comps[i] = new SecretKey.SKComponent();
			SK.comps[i].attr = attrs[i];
			SK.comps[i].Dj = g_r.mul(hash);
			SK.comps[i]._Dj = PK.gp.duplicate().powZn(rj);
		}
		System.out.println(SK.comps[0].Dj);
		SerializeUtils.serialize(SK, SKFile);
		SecretKey _SK = SerializeUtils.unserialize(SecretKey.class, SKFile);
		System.out.println(_SK.comps[0].Dj);
	}

	public static void enc(){
		
	}

	public static void dec(){
		
	}
}
