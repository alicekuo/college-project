import java.math.BigInteger;

public class RSA_Sign {
	BigInteger e,d,n;
	
	void initSign(BigInteger n, BigInteger d){	//用私鑰簽章
		this.n = n;
		this.d = d;
	}
	
	void initVerify(BigInteger n, BigInteger e){	//用公鑰驗證
		this.n = n;
		this.e = e;
	}
	
	BigInteger sign(BigInteger m){
		BigInteger s = m.modPow(d, n);	// s = m^d mod n 密文
		return s;
	}
	
	BigInteger verify(BigInteger s){
		BigInteger m = s.modPow(e, n);	// m = s^e mod n 明文
		return m;
	}
}
