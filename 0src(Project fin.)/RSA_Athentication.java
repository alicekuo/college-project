import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;

public class RSA_Athentication {
	public static void main(String[] args) throws Exception{
		
		BigInteger e,n,d,data,digest,sign,digest_new;
		RSA_Sign rsa = new RSA_Sign();
		
		//Ū��PublicKey�ɮ�
		File f = new File("PublicKey_front.txt");
		FileReader fr = new FileReader(f);
		BufferedReader br = new BufferedReader(fr);
		n = new BigInteger(br.readLine());
		e = new BigInteger(br.readLine());
		System.out.println("PublicKey:");
		System.out.println("n= "+n.toString());	//�p�G�n��16�i��-> toString(16)
		System.out.println("e= "+e.toString()+"\n");
		fr.close();
		
		//Ū��data�ɮ�
		f = new File("Data_front.txt");
		fr = new FileReader(f);
		br = new BufferedReader(fr);
		data = new BigInteger(br.readLine());
		System.out.println("�T�����e:");
		System.out.println("data= "+data.toString());			//�p�G�n��16�i��-> toString(16)
		System.out.println("message= "+message(BigIntegerToByte(data)));
		fr.close();		
		
		//Ū��sign�ɮ�
		f = new File("Digest_front.txt");
		fr = new FileReader(f);
		br = new BufferedReader(fr);
		sign = new BigInteger(br.readLine());
		System.out.println("\n�εo�e�̪��p�_�[�K�L���T���K�n:");
		System.out.println("sign= "+sign.toString()+"\n");	//�p�G�n��16�i��-> toString(16)
		fr.close();	
		
		//�ѱK�εo�e�̪����_�Ѷ}
		rsa.initVerify(n, e);
		digest_new = rsa.verify(sign);
		System.out.println("Digest_new: " + digest_new.toString());
		
		//�Φ��쪺�T���ghash�o��digest
		digest = new BigInteger(hash_sha(data.toString()));
		System.out.println("Digest    : " + digest.toString()+"\n");
		
		//�T�{digest�Mdigest_new�O�_�ۦP
		if(digest_new.equals(digest))
			System.out.println("�������ҥ��T");
		else
			System.out.println("�������ҿ��~");
		
	}
	
	public static String operate_code(String str) throws Exception{
		String finstr = "";
		byte[] b = str.getBytes();	//�w�]�HBIG5�s�X
		for(int i=0; i<b.length; i++)
			finstr += (b[i] & 0xff);
		return finstr;
	}
	
	public static String message(byte[] by) throws Exception{
		return new String(by);
	}
	
	public static byte[] BigIntegerToByte(BigInteger data){
		String str = data.toString();
		int count = 0;					//�Ψӭp��Byte[]�j�p
		int[] ByteToInt = new int[100];	//�N�T����Byte��int���Ȧs���A�w�]�j�p��100	
		byte[] databytearray;
		int t = 0;						//�M�w���X��bit���@��byte
		for(int i=0; i < str.length(); i += t, count++){
			if(str.charAt(i)<'3')			//�Y�C��byte�Ĥ@��bit��<3���ơA�h������r
				t = 3;					//��3��bits���@��byte
			else						//�Ϥ��A�C��byte�Ĥ@��bit��>3����(��ASCII���i���r��)�A�h���^��j�p�g�r���μƦr		
				t = 2;					//��2��bits���@��byte
			ByteToInt[count] = Integer.parseInt(str.substring(i, i+t));	//�N�T������2��3���@��byte�Aeg:��=179 162(2bytes)	
		}
		databytearray = new byte[count];	//�^�ǰT����byte[]
		for(int i=0; i < databytearray.length; i++)
			databytearray[i] = (byte)ByteToInt[i];	//�A��Ȧs������byte���e��idatabytearray
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
