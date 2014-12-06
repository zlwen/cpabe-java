package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

import cn.edu.pku.ss.crypto.abe.serialize.SimpleSerializable;

public class Policy implements SimpleSerializable{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	String attr;       /* attribute string if leaf, otherwise null */
	Element Cy;      /* G_1, only for leaves */
	Element _Cy;     /* G_1, only for leaves */
//	List<Policy> children; /* pointers to bswabe_policy_t's, len == 0 for leaves */
	Policy[] children;
	
	/* only used during encryption */
	transient Polynomial q;

	/* only used during decryption */
	transient int satisfiable;
	transient int min_leaves;
	transient int attri;
	transient List<Integer> satl;
}