namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            //Calculate C = M^e mod n when M is too large
            int c = largepower(M, e, n);
            return c;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int d;
            int n = p * q;
            int Euler = (p - 1) * (q - 1);
            //d= einverse mod euler 
            d = mulinverse(e, Euler);
            //Calculate M=C^d mod n when C is too large
            int M = largepower(C, d, n);
            return M;
        }

        //bt7sb el mod lama ykon el rkm kber
        public int largepower(int M, int e, int n)
        {
            long result = 1;
            long baseValue = M % n;
            while (e > 0)
            {
                if ((e & 1) == 1)
                {
                    result = (result * baseValue) % n;
                }
                baseValue = (baseValue * baseValue) % n;
                e >>= 1;
            }
            return (int)result;
        }

        //bt7sb el multiplicative inverse 3shan ngeb el d fl decrypt
        public int mulinverse(int a, int m)
        {
            int m0 = m;
            int y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {

                int q = a / m;
                int t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }


    }
}
