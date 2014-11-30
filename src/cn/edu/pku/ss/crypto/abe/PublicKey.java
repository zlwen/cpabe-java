package cn.edu.pku.ss.crypto.abe;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;

import cn.edu.pku.ss.crypto.abe.serialize.SimpleSerializable;

public class PublicKey implements SimpleSerializable {
	Element g; // G1 generator
	Element gp; // G2 generator
	Element g_hat_alpha; // GT
	Element h; //G1

}
