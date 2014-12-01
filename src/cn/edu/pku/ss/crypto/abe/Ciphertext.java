package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;
import cn.edu.pku.ss.crypto.abe.serialize.SimpleSerializable;

public class Ciphertext implements SimpleSerializable{
	Policy p;
	Element Cs; //GT
	Element C;  //G1
}
