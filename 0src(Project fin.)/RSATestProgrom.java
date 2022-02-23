import java.io.*;
import java.math.BigInteger;
import java.util.Scanner;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RSATestProgrom {	//測試嵌入資料程式，class前面多加final為不公開繼承
	
	public static void main(String[] args) throws Exception{
		//int pos=0;
		String SN="1014",data = null, data_sha = null;
		
		Scanner Scanner = new Scanner(System.in);	//鍵盤輸入
		System.out.print("請輸入要嵌入的資訊：");
		data = operate_code(Scanner.next());
		System.out.println("編碼後的嵌入資訊：" + data);
		data_sha = (hash_sha(data));
		System.out.println("編碼後的Hash值(前16碼)：" + data_sha);
//		System.out.print("請輸入要將資訊自第幾位開始嵌入：");
//		pos = Scanner.nextInt();
		
		//Front(嵌入的訊息,hash值,嵌入位置,嵌入方式,2048)
		RSAKeyGen_Front front = new RSAKeyGen_Front(SN,data, data_sha, 2048);
		front.KeyGen();	//產生key
		System.out.println("Strength = "+front.getStrength());
		System.out.println("p = "+front.getP().toString());	//toString()->10進位
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
		byte[] b = str.getBytes("BIG5");	//預設以BIG5編碼
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
