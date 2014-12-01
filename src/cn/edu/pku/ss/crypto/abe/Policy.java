package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class Policy{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	String attr;       /* attribute string if leaf, otherwise null */
	Element Cy;      /* G_1, only for leaves */
	Element _Cy;     /* G_1, only for leaves */
	List<Policy> children; /* pointers to bswabe_policy_t's, len == 0 for leaves */

	/* only used during encryption */
	Polynomial q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	List<Integer> satl;
}