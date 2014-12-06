package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import cn.edu.pku.ss.crypto.abe.serialize.SerializeUtils;

public class CPABE {
	private static Pairing pairing = PairingManager.defaultPairing;

	public static void main(String[] args) {
		setup();
	}
	
	public static void setup(String PKFileName, String MKFileName){
//		File PKFile = new File(PKFileName);
//		File MKFile = new File(MKFileName);
//		if(!PKFile.exists()){
//			try {
//				PKFile.createNewFile();
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//		}
//		if(!MKFile.exists()){
//			try {
//				MKFile.createNewFile();
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//		}
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
		String[] attrs = new String[]{"北京大学0", "北京大学2", "北京大学4"};
		SecretKey SK = keygen(attrs, PK, MK, null);
		Policy p = testPolicy();
		Element m = pairing.getGT().newElement().setToRandom();
		System.out.println(m);
		Ciphertext ciphertext = enc(p, m, PK, "a.out");
		
		dec(ciphertext, SK, PK);
	}
	
	private static Policy testPolicy(){
		Policy root = new Policy();
//		root.children = new ArrayList<Policy>();
		root.children = new Policy[5];
		root.k = 3;
		
		for(int i=0; i<5; i++){
			Policy child = new Policy();
			child.attr = "北京大学" + i;
			child.k = 1;
//			root.children.add(child);
			root.children[i] = child;
		}
		return root;
	}
	
	public static void setup(){
		String pk = "PubKey";
		String mk = "MasterKey";
		setup(pk, mk);
	}

	public static SecretKey keygen(String[] attrs, PublicKey PK, MasterKey MK, String SKFileName){
		if(SKFileName == null || SKFileName.trim().equals("")){
			SKFileName = "SecretKey";
		}
		File SKFile = createNewFile(SKFileName);
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
		
		SerializeUtils.serialize(SK, SKFile);
		System.out.println(SK.comps[2].Dj);
		SecretKey _SK = SerializeUtils.unserialize(SecretKey.class, SKFile);
		System.out.println(_SK.comps[2].Dj);
		return SK;
	}
	
	private static File createNewFile(String fileName){
		File file = new File(fileName);
		if(!file.exists()){
			try {
				file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		else{
			try {
				String path = file.getCanonicalPath();
				file.delete();
				file = new File(path);
				file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return file;
	}

	public static Ciphertext enc(Policy p, Element m, PublicKey PK, String ciphertextFileName){
		File ciphertextFile = createNewFile(ciphertextFileName);
		Element s = pairing.getZr().newElement().setToRandom();
		fill_policy(p, s, PK);
		Ciphertext ciphertext = new Ciphertext();
		ciphertext.p = p;
		ciphertext.Cs = m.mul(PK.g_hat_alpha.duplicate().powZn(s));
		ciphertext.C = PK.h.duplicate().powZn(s); 
		
		System.out.println(ciphertext.p.children[0].attr);
		SerializeUtils.serialize(ciphertext, ciphertextFile);
		Ciphertext _ciphertext = SerializeUtils.unserialize(Ciphertext.class, ciphertextFile);
		System.out.println(_ciphertext.p.children[0].attr);
		return ciphertext;
	}

	public static void dec(Ciphertext ciphertext, SecretKey SK, PublicKey PK){
		check_sat(SK, ciphertext.p);
		if(ciphertext.p.satisfiable != 1){
			System.err.println("SK does not satisfies the policy!");
			return;
		}
		pick_sat_min_leaves(ciphertext.p, SK);
		Element r = dec_flatten(ciphertext.p, SK);
		Element m = ciphertext.Cs.mul(r);
		r = pairing.pairing(ciphertext.C, SK.D);
		r.invert();
		m.mul(r);
		System.out.println("dec:" + m);
	}
	
	private static Element dec_flatten(Policy p, SecretKey SK){
		Element r = pairing.getGT().newElement().setToOne();
		Element one = pairing.getZr().newElement().setToOne();
		dec_node_flatten(r, one, p, SK);
		return r;
	}
	
	private static void dec_node_flatten(Element r, Element exp, 
			Policy p, SecretKey SK){
		assert(p.satisfiable == 1);
//		if(p.children == null || size == 0){
		if(p.children == null || p.children.length == 0){
			dec_leaf_flatten(r, exp, p, SK);
		}
		else{
			dec_internal_flatten(r, exp, p, SK);
		}
	}
	
	private static void dec_leaf_flatten(Element r, Element exp, 
			Policy p, SecretKey SK){
		SecretKey.SKComponent comp = SK.comps[p.attri];
		Element s = pairing.pairing(p.Cy, comp.Dj);
		Element t = pairing.pairing(p._Cy, comp._Dj);
		t.invert();
		s.mul(t);
		s.powZn(exp);
		r.mul(s);
	}
	
	private static void dec_internal_flatten(Element r, Element exp,
			 Policy p, SecretKey SK){
		int i;
		Element t;
		Element expnew;
		Element zero = pairing.getZr().newElement().setToZero();
		
		for(i=0; i<p.satl.size(); i++){
			t = lagrange_coef(p.satl, p.satl.get(i), zero);
			expnew = exp.duplicate().mul(t);    //注意这里的duplicate
//			dec_node_flatten(r, expnew, p.children.get(p.satl.get(i)-1), SK);
			dec_node_flatten(r, expnew, p.children[p.satl.get(i)-1], SK);
		}
	}

	
	private static void pick_sat_min_leaves(Policy p, SecretKey SK){
		int i,k,l;
		int size = p.children == null ? 0 : p.children.length;
		Integer[] c;
		assert(p.satisfiable == 1);
//		if(p.children == null || size == 0){
		if(p.children == null || p.children.length == 0){
			p.min_leaves = 1;
		}
		else{
//			for(i=0; i<size; i++){
//				if(p.children.get(i).satisfiable == 1){
//					pick_sat_min_leaves(p.children.get(i), SK);
//				}
//			}
			for(i=0; i<p.children.length; i++){
				if(p.children[i].satisfiable == 1){
					pick_sat_min_leaves(p.children[i], SK);
				}
			}
			
			c = new Integer[p.children.length];
			for(i=0; i<size; i++){
				c[i] = i;
			}
			
			Arrays.sort(c, new PolicyInnerComparator(p));
			p.satl = new ArrayList<Integer>();
			p.min_leaves = 0;
			l = 0;
			for(i=0; i<size && l<p.k; i++){
				if(p.children[i].satisfiable == 1){
					l++;
					p.min_leaves += p.children[i].min_leaves;
					k = c[i] + 1;
					p.satl.add(k);
				}
			}
			assert(l == p.k);
		}
	}
	
	private static class PolicyInnerComparator implements Comparator<Integer>{
		Policy p;
		public PolicyInnerComparator(Policy p){
			this.p = p;
		}
		
		@Override
		public int compare(Integer o1, Integer o2) {
			int k, l;
//			k = p.children.get(o1).min_leaves;
//			l = p.children.get(o2).min_leaves;
			
			k = p.children[o1].min_leaves;
			l = p.children[o2].min_leaves;
			return k < l ? -1 : k == l ? 0 : 1;
		}
		
	}
	
	private static void check_sat(SecretKey SK, Policy p){
		int i,l;
		int size = p.children == null ? 0 : p.children.length;
		p.satisfiable = 0;
		if(p.children == null || size == 0){
			for(i=0; i<SK.comps.length; i++){
				if(SK.comps[i].attr.equals(p.attr)){
					p.satisfiable = 1;
					p.attri = i;
					break;
				}
			}
		}
		else{
			for(i=0; i<size; i++){
				check_sat(SK, p.children[i]);
			}
			
			l = 0;
			for(i=0; i<size; i++){
				if(p.children[i].satisfiable == 1){
					l++;
				}
			}
			if(l >= p.k){
				p.satisfiable = 1;
			}
		}
	}
	
	
	public static void fill_policy(Policy p, Element e, PublicKey PK){
		int i;
		int size = p.children == null ? 0 : p.children.length;
		Element r, t;
		p.q = rand_poly(p.k - 1, e);
		if(p.children == null || size == 0){
			p.Cy = PK.g.duplicate().powZn(p.q.coef.get(0));
			p._Cy = pairing.getG1().newElementFromBytes(p.attr.getBytes()).powZn(p.q.coef.get(0));
		}
		else{
			for(i=0; i<size; i++){
				r = pairing.getZr().newElement().set(i+1);
				t = Polynomial.eval_poly(p.q, r);
				fill_policy(p.children[i], t, PK);
			}
		}
	}
	
	public static Polynomial rand_poly(int deg, Element zero_val){
		int i;
		Polynomial q = new Polynomial();
		q.deg = deg;
		q.coef = new ArrayList<Element>();

		q.coef.add(zero_val.duplicate());
		for(i=1; i<q.deg+1; i++){
			q.coef.add(pairing.getZr().newElement().setToRandom());
		}
		
		return q;
	}
	
	public static Element lagrange_coef(List<Integer> S, int i, Element x){
		int j,k;
		Element r = pairing.getZr().newElement().setToOne();
		Element t;
		for(k=0; k<S.size(); k++){
			j = S.get(k);
			if(j == i){
				continue;
			}
			t = x.duplicate().sub(pairing.getZr().newElement().set(j));   //注意这里的duplicate
			r.mul(t);
			t.set(i-j).invert();
			r.mul(t);
		}
		
		return r;
	}
}
