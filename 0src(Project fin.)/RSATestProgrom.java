import java.io.*;
import java.math.BigInteger;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RSATestProgrom {	//���մO�J��Ƶ{���Aclass�e���h�[final�������}�~��
	
	public static void main(String[] args) throws Exception{
		//int pos=0;
		String SN="1014",data = null, data_sha = null;
		
		Scanner Scanner = new Scanner(System.in);	//��L��J
		System.out.print("�п�J�n�O�J����T�G");
		data = operate_code(Scanner.next());
		System.out.println("�s�X�᪺�O�J��T�G" + data);
		data_sha = (hash_sha(data));
		System.out.println("�s�X�᪺Hash��(�e16�X)�G" + data_sha);
//		System.out.print("�п�J�n�N��T�۲ĴX��}�l�O�J�G");
//		pos = Scanner.nextInt();
		
		//Front(�O�J���T��,hash��,�O�J��m,�O�J�覡,2048)
		RSAKeyGen_Front front = new RSAKeyGen_Front(SN,data, data_sha, 2048);
		front.KeyGen();	//����key
		System.out.println("Strength = "+front.getStrength());
		System.out.println("p = "+front.getP().toString());	//toString()->10�i��
		System.out.println("q = "+front.getQ().toString());
		System.out.println("n = "+front.getN().toString());
		System.out.println("e = "+front.getE().toString());
		System.out.println("d = "+front.getD().toString());

		
		try{
			File f = new File("PublicKey_front.txt");
			front.exportPublicKey(f);
						
			File f1 = new File("PrivateKey_front.txt");
			front.exportPrivateKey(f1);
			
			File f2 = new File("Digest_front.txt");
			front.exportDigest(f2);
			
			File f3 = new File("Data_front.txt");
			front.exportData(f3);
		}
		catch(Exception e){
			System.out.println("File Error!");
		}
	}
	
	public static String operate_code(String str) throws Exception{
		String finstr = "";
		byte[] b = str.getBytes("BIG5");	//�w�]�HBIG5�s�X
		for(int i=0; i<b.length; i++)
			finstr += (b[i] & 0xff);
		return finstr;
	}
	
	public static String hash_sha(String str) throws Exception{
		String end = "";
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(str.getBytes());
		byte[] byteData = md.digest();
		for(int i=0; i<byteData.length; i++)
			end += (int)(byteData[i]&0xff);
		return end;

	}
}
