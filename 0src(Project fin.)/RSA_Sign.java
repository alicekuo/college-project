import java.math.BigInteger;

public class RSA_Sign {
	BigInteger e,d,n;
	
	void initSign(BigInteger n, BigInteger d){	//�Ψp�_ñ��
		this.n = n;
		this.d = d;
	}
	
	void initVerify(BigInteger n, BigInteger e){	//�Τ��_����
		this.n = n;
		this.e = e;
	}
	
	BigInteger sign(BigInteger m){
		BigInteger s = m.modPow(d, n);	// s = m^d mod n �K��
		return s;
	}
	
	BigInteger verify(BigInteger s){
		BigInteger m = s.modPow(e, n);	// m = s^e mod n ����
		return m;
	}
}
