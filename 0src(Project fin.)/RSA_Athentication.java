import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;

public class RSA_Athentication {
	public static void main(String[] args) throws Exception{
		
		BigInteger e,n,d,data,digest,sign,digest_new;
		RSA_Sign rsa = new RSA_Sign();
		
		//讀取PublicKey檔案
		File f = new File("PublicKey_front.txt");
		FileReader fr = new FileReader(f);
		BufferedReader br = new BufferedReader(fr);
		n = new BigInteger(br.readLine());
		e = new BigInteger(br.readLine());
		System.out.println("PublicKey:");
		System.out.println("n= "+n.toString());	//如果要轉16進制-> toString(16)
		System.out.println("e= "+e.toString()+"\n");
		fr.close();
		
		//讀取data檔案
		f = new File("Data_front.txt");
		fr = new FileReader(f);
		br = new BufferedReader(fr);
		data = new BigInteger(br.readLine());
		System.out.println("訊息內容:");
		System.out.println("data= "+data.toString());			//如果要轉16進制-> toString(16)
		System.out.println("message= "+message(BigIntegerToByte(data)));
		fr.close();		
		
		//讀取sign檔案
		f = new File("Digest_front.txt");
		fr = new FileReader(f);
		br = new BufferedReader(fr);
		sign = new BigInteger(br.readLine());
		System.out.println("\n用發送者的私鑰加密過的訊息摘要:");
		System.out.println("sign= "+sign.toString()+"\n");	//如果要轉16進制-> toString(16)
		fr.close();	
		
		//解密用發送者的公鑰解開
		rsa.initVerify(n, e);
		digest_new = rsa.verify(sign);
		System.out.println("Digest_new: " + digest_new.toString());
		
		//用收到的訊息經hash得到digest
		digest = new BigInteger(hash_sha(data.toString()));
		System.out.println("Digest    : " + digest.toString()+"\n");
		
		//確認digest和digest_new是否相同
		if(digest_new.equals(digest))
			System.out.println("身分驗證正確");
		else
			System.out.println("身分驗證錯誤");
		
	}
	
	public static String operate_code(String str) throws Exception{
		String finstr = "";
		byte[] b = str.getBytes();	//預設以BIG5編碼
		for(int i=0; i<b.length; i++)
			finstr += (b[i] & 0xff);
		return finstr;
	}
	
	public static String message(byte[] by) throws Exception{
		return new String(by);
	}
	
	public static byte[] BigIntegerToByte(BigInteger data){
		String str = data.toString();
		int count = 0;					//用來計算Byte[]大小
		int[] ByteToInt = new int[100];	//將訊息自Byte轉int的暫存器，預設大小為100	
		byte[] databytearray;
		int t = 0;						//決定取幾個bit為一個byte
		for(int i=0; i < str.length(); i += t, count++){
			if(str.charAt(i)<'3')			//若每個byte第一個bit為<3的數，則為中文字
				t = 3;					//取3個bits為一個byte
			else						//反之，每個byte第一個bit為>3的數(為ASCII中可視字元)，則為英文大小寫字母或數字		
				t = 2;					//取2個bits為一個byte
			ByteToInt[count] = Integer.parseInt(str.substring(i, i+t));	//將訊息中取2或3為一個byte，eg:郭=179 162(2bytes)	
		}
		databytearray = new byte[count];	//回傳訊息為byte[]
		for(int i=0; i < databytearray.length; i++)
			databytearray[i] = (byte)ByteToInt[i];	//再把暫存器中的byte內容放進databytearray
		return databytearray;
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
