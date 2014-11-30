package cn.edu.pku.ss.crypto.abe.serialize;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;

import cn.edu.pku.ss.crypto.abe.PairingManager;

public class SerializeUtils {
	public static <T extends SimpleSerializable> T unserialize(Class<T> clazz, File file) {
		T t = null;
		DataInputStream dis = null;
		Field[] fields = clazz.getDeclaredFields();
		try {
			t = clazz.newInstance();
			dis = new DataInputStream(new FileInputStream(file));

			for (Field field : fields) {
				byte mark = dis.readByte();
				if (field.getType() == Element.class) {
					if (mark != SimpleSerializable.ElementMark) {
						System.err.println("serialize error!");
						return null;
					}
					Element e = null;
					int len = dis.readInt();
					byte[] buffer = new byte[len];
					String name = field.getName();
					dis.read(buffer);
					if(name.equals("g") || name.equals("h")){
						e = PairingManager.defaultPairing.getG1().newElementFromBytes(buffer);
					}
					else if(name.equals("gp") || name.equals("g_alpha")){
						e = PairingManager.defaultPairing.getG2().newElementFromBytes(buffer);
					}
					else if(name.equals("g_hat_alpha")){
						e = PairingManager.defaultPairing.getGT().newElementFromBytes(buffer);
					}
					else if(name.equals("beta")){
						e = PairingManager.defaultPairing.getZr().newElementFromBytes(buffer);
					}
					field.setAccessible(true);
					field.set(t, e);
				}
				else if(field.getType().isArray()){
					if(mark != SimpleSerializable.ArrayMark){
						System.err.println("serialize error!");
						return null;
					}
					int arrlen = dis.readInt();
					Element[] es = new Element[arrlen];
					for(int i=0; i<arrlen; i++){
						mark = dis.readByte();
						if(mark != SimpleSerializable.ElementMark){
							System.err.println("serialize error!");
							return null;
						}
						int len = dis.readInt();
						byte[] buffer = new byte[len];
						String name = field.getName();
						dis.read(buffer);
						if(name.equals("C")){
							es[i] = PairingManager.defaultPairing.getG1().newElementFromBytes(buffer);
						}
						else if(name.equals("D")){
							es[i] = PairingManager.defaultPairing.getG2().newElementFromBytes(buffer);
						}
					}
					field.setAccessible(true);
					field.set(t, es);
				}
			}
		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return t;
	}

	public static <T extends SimpleSerializable> void serialize(T obj, File file) {
		if (file == null) {
			System.err.println("Must set the file to hold key!");
			return;
		}
		Field[] fields = obj.getClass().getDeclaredFields();
		DataOutputStream dos = null;
		try {
			dos = new DataOutputStream(new FileOutputStream(file));
			for (Field field : fields) {
				if (field.getType() == Element.class) {
					field.setAccessible(true);
					Element e = (Element) field.get(obj);
					dos.writeByte(SimpleSerializable.ElementMark);
					dos.writeInt(e.toBytes().length);
					dos.write(e.toBytes());
				} else if (field.getType().isArray()) {
					field.setAccessible(true);
					Array array = (Array) field.get(obj);
					int len = Array.getLength(array);
					dos.writeByte(SimpleSerializable.ArrayMark);
					dos.writeInt(len);
					for (int i = 0; i < len; i++) {
						Element e = (Element) Array.get(array, i);
						dos.writeByte(SimpleSerializable.ElementMark);
						dos.writeInt(e.toBytes().length);
						dos.write(e.toBytes());
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
