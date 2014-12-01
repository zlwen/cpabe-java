package cn.edu.pku.ss.crypto.abe.serialize;

import it.unisa.dia.gas.jpbc.Element;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import cn.edu.pku.ss.crypto.abe.PairingManager;
import cn.edu.pku.ss.crypto.abe.Policy;
import cn.edu.pku.ss.crypto.abe.SecretKey.SKComponent;

public class SerializeUtils {
	private static <T extends SimpleSerializable> T _unserialize(
			Class<T> clazz, DataInputStream dis) {
		T t = null;
		Field[] fields = clazz.getDeclaredFields();
		try {
			t = clazz.newInstance();
			for (Field field : fields) {
				field.setAccessible(true);
				byte mark = dis.readByte();
				// unserialize Element
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
					if (name.equals("g") || name.equals("h")) {
						e = PairingManager.defaultPairing.getG1()
								.newElementFromBytes(buffer);
					} else if (name.equals("gp") || name.equals("g_alpha")
							|| name.equals("D") || name.equals("Dj")
							|| name.equals("_Dj")) {
						e = PairingManager.defaultPairing.getG2()
								.newElementFromBytes(buffer);
					} else if (name.equals("g_hat_alpha")) {
						e = PairingManager.defaultPairing.getGT()
								.newElementFromBytes(buffer);
					} else if (name.equals("beta")) {
						e = PairingManager.defaultPairing.getZr()
								.newElementFromBytes(buffer);
					}
					field.set(t, e);
				}
				// unserialize String
				else if (field.getType() == String.class) {
					if (mark != SimpleSerializable.StringMark) {
						System.err.println("serialize error!");
						return null;
					}
					String s = dis.readUTF();
					field.set(t, s);
				}
				// unserialize SKComponent
				else if (field.getType() == SKComponent.class) {
					if (mark != SimpleSerializable.SKComponentMark) {
						System.err.println("serialize error!");
						return null;
					}
					SKComponent comp = _unserialize(SKComponent.class, dis);
					field.set(t, comp);
				}
				// unserialize SKComponent Array
				else if (field.getType().isArray()) {
					if (mark != SimpleSerializable.ArrayMark) {
						System.err.println("serialize error!");
						return null;
					}
					Class<?> c = field.getType().getComponentType();
					int arrlen = dis.readInt();
					if (c == SKComponent.class) {
						SKComponent[] comps = new SKComponent[arrlen];
						for (int i = 0; i < arrlen; i++) {
							comps[i] = _unserialize(SKComponent.class, dis);
						}
						field.set(t, comps);
					}
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

	public static <T extends SimpleSerializable> T unserialize(Class<T> clazz,
			File file) {
		DataInputStream dis = null;
		try {
			dis = new DataInputStream(new FileInputStream(file));
			return _unserialize(clazz, dis);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} finally {
			try {
				dis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	private static <T extends SimpleSerializable> void _serialize(T obj,
			DataOutputStream dos) {
		Field[] fields = obj.getClass().getDeclaredFields();
		try {
			for (Field field : fields) {
				field.setAccessible(true);
				if (Modifier.isTransient(field.getModifiers())) {
					continue;
				}
				Class<?> type = field.getType();
				if (type == Element.class) {
					Element e = (Element) field.get(obj);
					dos.writeByte(SimpleSerializable.ElementMark);
					dos.writeInt(e.toBytes().length);
					dos.write(e.toBytes());
				} else if (type == String.class) {
					String s = (String) field.get(obj);
					dos.writeByte(SimpleSerializable.StringMark);
					dos.writeUTF(s);
				} else if (type == int.class) {
					int i = field.getInt(obj);
					dos.writeByte(SimpleSerializable.IntMark);
					dos.writeInt(i);
				} else if (type == Policy.class) {
					Policy p = (Policy) field.get(obj);
					dos.writeByte(SimpleSerializable.PolicyMark);
					_serialize(p, dos);
				} else if (type.isArray()) {
					Class<?> clazz = type.getComponentType();
					if (clazz == SKComponent.class) {
						SKComponent[] array = (SKComponent[]) field.get(obj);
						int len = array.length;
						dos.writeByte(SimpleSerializable.ArrayMark);
						dos.writeInt(len);
						for (int i = 0; i < len; i++) {
							SKComponent comp = array[i];
							dos.writeByte(SimpleSerializable.SKComponentMark);
							_serialize(comp, dos);
						}
					}
					else if(clazz == Policy.class){
						Policy[] array = (Policy[]) field.get(obj);
						int len = array.length;
						dos.writeByte(SimpleSerializable.ArrayMark);
						dos.writeInt(len);
						for (int i = 0; i < len; i++) {
							Policy p = array[i];
							dos.writeByte(SimpleSerializable.PolicyMark);
							_serialize(p, dos);
						}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}
	}

	public static <T extends SimpleSerializable> void serialize(T obj, File file) {
		DataOutputStream dos = null;
		try {
			dos = new DataOutputStream(new FileOutputStream(file, true));
			_serialize(obj, dos);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				dos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
