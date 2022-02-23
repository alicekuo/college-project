import java.math.BigDecimal;
import java.math.BigInteger;
import java.io.*;
import java.security.SecureRandom;
import java.util.Random;

public class RSAKeyGen_Front {
	// input: embadded portion s
	// output: RSA modulus n = pq = s || r
	// EX: s=53 p=6067
	// Goal: 53xxxxxx	
	
	private BigInteger p,q,n,e,d,phi_n,srndN,tmp,qq;
	private int strength,pos,rnd,r,rr,nlen,tmplen;
	private SecureRandom srnd = new SecureRandom();	//��������
	private String SN,data,value,data_sha;
	private BigInteger digest,signature;
	private BigDecimal div,ceil,bdp;
	RSA_Sign rsa = new RSA_Sign();
	
	public RSAKeyGen_Front(String SN, String data,String data_sha,int strength){	//撱箸���痊���迄隞���
		this.SN = SN;
		this.data = data;
		this.data_sha = data_sha;
		//this.pos = pos;
		this.strength = strength;
	}
	
	public RSAKeyGen_Front(){		//撱箸���痊���迄隞���嚗verload���迂銝��
		this.SN = "1014";	//霅���
		this.data = "";			//鞈��
		this.data_sha = "";		//hash code
		//this.pos = 0;				//蝚砍嗾��蔭
		this.strength = 2048;		//撘瑕漲2048雿��(鞈芣���之)
	}
	
	public int getStrength(){	return strength;	}
	public BigInteger getP(){	return p;	}
	public BigInteger getQ(){	return q;	}
	public BigInteger getN(){	return n;	}
	public BigInteger getE(){	return e;	}
	public BigInteger getD(){	return d;	}
	//public int getrnd(){	return rnd;	}	//蝯刖UI隞��鈭

	/*閮餉����:
	 * Generate 2 prime p,q;
	 * Evaluate n=p*q;
	 * Set e=65537;			//e,���(n)=1
	 * Evaluate d = e^-1 mod ���(n);
	 * ���(n) = (p-1)(q-1) = pq-p-q+1 = n-p-q+1
	 */
	
	public void KeyGen(){	
			p = BigInteger.probablePrime(strength/2, srnd);
			bdp = new BigDecimal(p);
//			if(pos!=1){	//敺洵鈭����
//				do{	//nextInt()嚗����葡頧���
//					rnd = (Math.abs(srnd.nextInt())) % (int)(Math.pow(10, pos-1));	//rnd = (int)|srnd| mod (int)10^(pos-1) = pos-1雿���
//				}while(String.valueOf(rnd).length() != pos-1);	//�摮葡����nd�隞嗥�摨� != pos-1 餈游��迫
//				System.out.println("鈭 = " + rnd);	//憿舐內鈭���
//				value = Integer.toString(rnd) + SN + data + data_sha;	//value = 鈭+霅���+鞈��+hash
//			}		
//			else{	//敺洵銝�雿���
//				value = SN + data + data_sha;	//value = 鞈��+hash
//			}
			value = SN + data + data_sha;
			tmp = new BigInteger(value);	//tmp = value
			
			nlen = (int)Math.ceil(2048*Math.log10(2));	//n����
			tmplen = tmp.toString().length();			//tmp(��撋�����)��嗾雿
			rr = nlen - tmplen;		// |r|
			//System.out.println("nlen=" + nlen +"\ttmplen=" + tmplen +"\t|r|="+rr);
			srndN = new BigInteger(rr,srnd);
			BigDecimal NN = new BigDecimal(srndN);
			div = new BigDecimal(tmp.multiply((BigInteger.TEN).pow(rr)));
			ceil = div.divide(bdp, BigDecimal.ROUND_CEILING);
			q = ceil.add(NN).toBigInteger().nextProbablePrime();

//			System.out.println("q'="+qq);
//			System.out.println("q'len="+qq.bitLength());
			
//			BigInteger z = new BigInteger
//					((int)Math.ceil((strength-tmp.bitLength())*Math.log10(2)),new SecureRandom());
//			while(strength > tmp.bitLength()) tmp = tmp.multiply(BigInteger.TEN);	
//			tmp = tmp.add(z);
//			q = (tmp.divide(p)).nextProbablePrime();//��range
			
			//r = (int) (Math.log(1024)-Math.log(Math.log10(strength)));
//			srndN = new BigInteger(rr,srnd);	//srndN�銝��璈���嚗��0�2^(2048-n��itlength)-1
//			
//			q = qq.add(srndN);//
			
			//瘜冽�釣���!!
			n = p.multiply(q);	// n = p*q
//			srndN = new BigInteger(strength-tmp.bitLength(),srnd);
//			n = n.add(srndN);
			e = new BigInteger("65537");	//e=65537
			phi_n = n.subtract(p).subtract(q).add(BigInteger.ONE);//���(n) = (p-1)(q-1) = pq-p-q+1 = n-p-q+1
			
			System.out.println("qlen="+q.bitLength());
			System.out.println("bitlen="+n.bitLength());
			
			try {//靘��瘜�
				d = e.modInverse(phi_n);	//d = e^-1 mod ���(n)
			}
			catch(ArithmeticException e){
				System.out.println("No Inverse Element!");
				d = new BigInteger("-1");
			}
		}

	public static BigInteger rand(int i) {
        String str = "";
 
        while (str.length() < i) {
            int x = (int) (Math.random() * 9 + 1); //�見�摮������ 10 
            if (!str.contains(String.valueOf(x))) 	str +=x;
        }
            return new BigInteger(str);
    }
	
	public void exportPublicKey(File f){
		try{
			FileWriter fw = new FileWriter(f);	//Writer �虜�撖怠������������
			fw.write(n.toString()+"\n");
			fw.write(e.toString());
			fw.close();
		}
		catch(Exception e){
			System.out.println("PublicKey can't wirte in the file.");
		}
	}
	
	public void exportPrivateKey(File f){
		try{
			FileWriter fw = new FileWriter(f);	//Writer �虜�撖怠������������
			fw.write(n.toString()+"\n");
			fw.write(d.toString());
			fw.close();
		}
		catch(Exception e){
			System.out.println("PrivateKey can't wirte in the file.");
		}
	}	
	
	public void exportDigest(File f){
		try{
			FileWriter fw = new FileWriter(f);	//Writer �虜�撖怠������������
			//�蝘���igest霈�ignature
			digest = new BigInteger(data_sha);
			rsa.initSign(n, d);
			signature = rsa.sign(digest);

			fw.write(signature.toString());
			fw.close();
		}
		catch(Exception e){
			System.out.println("Digest can't wirte in the file.");
		}
	}
	
	public void exportData(File f){
		try{
			FileWriter fw = new FileWriter(f);	//Writer �虜�撖怠������������
			fw.write(data);			
			fw.close();
		}
		catch(Exception e){
			System.out.println("Data can't wirte in the file.");
		}
	}

}
